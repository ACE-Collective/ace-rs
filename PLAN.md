# ACE rebuild plan

This plan breaks [DESIGN.md](DESIGN.md) into steps that are each one reviewed change. Every step says what to build and ends with "Done when", the check that shows it works.

Phase 0 sets up the workspace and takes the first build measurement. Phases 1 to 4 follow DESIGN.md's *Sequence* steps 1 to 4, except that phase 3 compares against ace3 on local samples instead of production traffic. Sequence step 5 is split into phases 5 to 7.

Paths that start with `ace3/` are in the checkout at `../ace3`, read at commit `141a60a2` on 2026-10-29. Issue numbers are in [ACE-Collective/ace3](https://github.com/ACE-Collective/ace3/issues). The table at the end maps each of the 43 design-flaw issues to the step that removes its cause.

## Scope

For now ace4 is a proof of concept that runs on one laptop beside ace3. ace3 sends ace4 nothing. The comparisons use files already on the laptop, because the SVS corpus lives in production. Moving data out of ace3, comparing against production traffic, production deployment and cutover wait until there's a decision to take ace4 further. *Deferred* at the end lists them.

## Rules for every step

- A step is one change, with its tests in the same change.
- A step needs the steps above it in its phase, unless it names its own dependencies.
- A measurement records the command, the number of runs, the median and the range, and what else the number could include, such as cached work, errors or skipped steps.
- A ported module is done when its output matches ace3's: on reference dumps in phase 1 (1.24), and in 3.3's comparison over the local samples from phase 3 on. From phase 5 on, a port also brings its analysis template.
- No step changes ace3's checkout, the signatures repository or the site_ace repository. Scripts that need ace3's code live in `tools/ace3/` and run in ace3's dev container through `docker exec`.
- A step that ports something ace3 integrations can extend also adds it to `ace-app` (2.31), so site_ace can extend it too.
- A step that changes a Compose file keeps ace4's stack able to run beside ace3's, following *Running beside ace3* below. 0.6's check enforces it.

## Crates

Each crate is added by the step in the last column.

| Crate | Holds | Added in |
|---|---|---|
| `ace-layering` | the CI check that keeps `ace-results`, `ace-api`, `ace-gui` and `ace-search` off `ace-mod-*` crates | 0.4 |
| `ace-yara` | ACE's two YARA scanner layers on yara-x | 1.1 |
| `ace` | the binary: CLI, API, GUI, orchestrator, scheduler | 1.8 |
| `ace-results` | observable kinds, result types, the type registry, JSON Schema export | 1.14 |
| `ace-sdk` | the module traits, manifests, task context, HTTP client, file output | 1.18 |
| `ace-testkit` | the module test harness | 1.23 |
| `ace-mod-*` | one crate per analysis module or module family | 1.25 |
| `ace-core` | schema, queue, eligibility, lease API, submissions | 2.2 |
| `ace-store` | the content-addressed bucket client and node cache | 2.5 |
| `ace-pool` | the pool runtime: lease loop, task supervisor, containment | 2.16 |
| `ace-app` | builds the `ace` and pool binaries from a list of crates, here and in site repositories | 2.31 |
| `ace-service` | the service layer: actors, permissions, audit | 5.1 |
| `ace-api` | the JSON adapter | 5.5 |
| `ace-gui` | the HTML adapter | 5.7 |
| `ace-search` | the search indexer | 7.11 |

## Running beside ace3

ace4's stack has to run on the laptop at the same time as ace3's. ace3 keeps its own instances apart by project name, host ports and image tags (`ace3/docs/MULTI_INSTANCE.md`), and ace4 stays clear of all three.

- **Project name.** ace4's Compose file sets `name: ${ACE4_STACK:-ace4}`. ace3's default project is `ace`, and its extra instances take their names from `ACE_STACK`, so no ace3 instance may be named `ace4`. Compose derives container, network and volume names from the project name, so ace4 sets no `container_name` and gives no volume or network an explicit `name:`. `COMPOSE_PROJECT_NAME` overrides `name:` in both stacks, so ace4's `stack-guard` service refuses to start the stack when the project in use isn't `ACE4_STACK`. Compose can't tell that variable set to `ace4` from not set at all, so unlike ace3's `docker/startup/initialize_volumes.sh`, the guard refuses a different name rather than any value.
- **Variables.** Every ace4 variable starts with `ACE4_`, so a shell that exports ace3's `ACE_*` variables doesn't change ace4.
- **Host ports.** ace3 fixes five by default: 5000, 5001, 8443, 9443 and 24224. Each extra ace3 instance shifts all five by its offset, such as 100. ace4 fixes one, `ACE4_PORT_HTTPS` (default 7443), for the `ace` service. Postgres, MinIO and everything else publish on ephemeral ports bound to `ACE4_BIND_ADDRESS` (default `127.0.0.1`), as ace3's databases do.
- **Logs.** The stack logs to stdout. It doesn't use Docker's fluentd log driver, because that driver needs a fixed host port, and ace3 already holds 24224.
- **Images.** Every image ace4 builds is named `ace4-*`. ace3 builds `ace3`, `phishkit`, `phishkit-manager`, `js-deobfuscator` and `js-deobfuscator-manager`, all tagged `latest`, and a build in one checkout must not replace the other's images.
- **ace3's data.** ace4 reads ace3's data only through ace3's API, ace3's own commands run in its dev container, or read-only bind mounts of host directories. It never mounts an ace3 volume, and ace3 sends ace4 nothing.
- **Memory.** Both stacks share one Docker VM (Rancher Desktop on this laptop, 8 CPUs and 32 GB). ace4's defaults run one replica per pool, each with a `mem_limit`.

## Phase 0: workspace and the first build measurement

DESIGN.md names Rust's build time as one of the two results that could change the language pick, so the workspace gets its heavy dependencies before any ACE code.

- [x] **0.1 Workspace.** Create the Cargo workspace with a pinned `rust-toolchain.toml` and `[workspace.lints]` that deny `unused_must_use` and clippy's `let_underscore_must_use`. Done when a scratch crate containing `let _ = fallible();` fails `cargo clippy`.
- [x] **0.2 Dev container.** Add a `dev` Compose service with the toolchain, mold, sccache and bacon, with `target/` on a named volume instead of the macOS bind mount. Done when bacon in the container rebuilds after a save in the host checkout.
- [ ] **0.3 CI.** Run `cargo fmt --check`, `cargo clippy -- -D warnings` and `cargo test` on every push. Done when a formatting error fails CI.
- [ ] **0.4 Layering check.** Cargo rejects cycles between crates, but nothing stops a one-way dependency from the API on an analyzer. Add a CI check over `cargo metadata` that fails when `ace-results`, `ace-api`, `ace-gui` or `ace-search` depends on an `ace-mod-*` crate, directly or through another crate. Done when a scratch dependency from a crate named `ace-api` on one named `ace-mod-x` fails CI. (#1029, #1031, #1066, #843)
- [ ] **0.5 Build-loop spike.** In a throwaway crate, use tokio, axum, sqlx, askama, the AWS S3 SDK and yara-x once each. In the dev container on macOS and on CI's Linux runner, time a clean build, a no-op build, and the path from a one-line edit in a leaf crate to a runnable test binary, five runs each, noting whether sccache was warm. Done when `docs/measurements/build-loop.md` holds both machines' numbers.
- [ ] **0.6 Coexistence check.** `bin/check-coexistence` reads `docker compose config --format json` and fails on anything *Running beside ace3* rules out. That means a project name of `ace`, a host port in ace3's fixed list or one not set from an `ACE4_` variable, an image name that ace3 builds, a `container_name`, an explicitly named volume or network, and the fluentd log driver. CI runs it on every change to a Compose file. Done when CI runs it, and `docker compose up` in ace4 comes up healthy while ace3's default stack is running and ace3's services stay healthy.
- [x] **0.7 No install path.** Nothing assumes where the checkout lives (#920). Done when the stack runs from a checkout moved to another directory.
- [x] **0.8 Local sample set.** Gather the files the comparisons use: ace3's test fixtures, such as the emails under `ace3/tests/saq/modules/test_email/emails/`, and files added by hand. Cover each kind of file the phase 1 and phase 4 modules read: emails, archives (zip, 7z, RAR and password-protected ones), PDFs, Office files with macros, and RTF. Later ports add samples for the files they read. `samples/manifest.json` records each file's sha256, where it came from, its path inside an alert and the meta tags it would carry. Files that didn't come from ace3's repository stay out of git. Done when the manifest covers every kind of file listed here.

## Phase 1: results crate, module SDK and five modules

Track A is the YARA scanner. It holds the other result that could change the language pick, so it starts first, alongside track B. Track C needs 1.23 and 1.24 from track B, and its YARA step needs track A. Phase 1 ends with a decision in 1.32.

### Track A: the YARA scanner

- [ ] **1.1 Rule loading.** In `ace-yara`, load a signature directory the way `yara_scanner_v2` 3.0.0 does. Each subdirectory is a namespace. Each rule file compiles alone first, and a file that fails is logged at ERROR with its path and left out. The other files then compile together. Set the default externals `filename`, `filepath` and `extension`, and skip blacklisted rule names. Done when a fixture directory with one broken file loads every other rule and logs the broken file.
- [ ] **1.2 Meta filter.** Port the post-scan filter for the five directives in DESIGN.md's table: `meta_tags`, `file_name`, `mime_type`, `full_path` and `file_ext`. A value is a comma-separated list and the rule is kept if any item matches, ignoring case. `!` negates the list, `re:` makes each item a regex search, and `sub:` makes it a substring test. A non-negated `meta_tags` drops the rule when the caller passes no tags. Done when a table-driven test covers each directive with each prefix, plus the no-tags case.
- [ ] **1.3 Regex directives at build time.** Compile every `re:` value with the `regex` crate while loading rules, and leave out the rule's file when one fails. Done when a fixture rule with a lookaround in `re:` leaves its file out, with an ERROR that names the pattern.
- [ ] **1.4 Rule meta.** Port `ace3/saq/signatures/yara_meta.py`: `enabled`, the rule uuid and `modifiers`. Port `no_alert` as well as `qa`, since `ace3/saq/svs/yara/diff.py` treats both as "never alerts" and DESIGN.md names only `qa`. Done when the cases in `ace3/tests/saq/signatures/test_yara_meta.py` pass as Rust tests.
- [ ] **1.5 Scan.** Scan bytes with the externals taken from the file's name and its path inside the alert, the caller's meta tags, the mime type and a timeout. Each match returns the namespace, rule, meta and pattern offsets. Done when a fixture scan returns offsets and a scan past its timeout returns a timeout error, not an empty match list.
- [ ] **1.6 Rulesets.** Serialize a compiled ruleset to bytes and key it by hash, with a manifest of the commit, the yara-x version, the files and rules included and the files left out (#1051). A rule directory outside git is keyed by the hash of its sources. Done when two builds of the same commit give the same key. If yara-x's serialization isn't deterministic, key by (commit, yara-x version) instead, and say so in the test.
- [ ] **1.7 Mime type.** Compute the mime type with libmagic from a magic database pinned in the image. Done when it agrees with `file -b --mime-type` on a fixture set. Step 1.11 compares it over the whole sample set.
- [ ] **1.8 `ace yara scan`.** Add the command to the `ace` binary: scan a file with a ruleset, taking meta tags and a path. Done when it prints the same rules as ace3's `ace yara scan` for three fixture files.
- [ ] **1.9 ace3's replay child, with offsets.** `ace3/saq/svs/yara/child.py` records the namespace, rule and meta of each match (`child.py:229`), but not pattern offsets. It imports only the standard library, yara and yara_scanner, so a copy in `tools/ace3/` with offsets added runs on ace3's Python in ace3's dev container. Done when the copy writes offsets for a working directory of local files.
- [ ] **1.10 Rust replay child.** `ace yara replay <workdir>` reads a `job.json` in the shape `ace3/saq/svs/yara/replay.py` writes, and writes `result.json` in 1.9's shape. A script in `tools/ace3/` builds that working directory from 0.8's samples, one unit per (file, path inside the alert, meta tags). Done when both children run on the same working directory.
- [ ] **1.11 Comparison.** Compile every rule file in ace3's signatures checkout with both scanners, and list the files each one leaves out. That half needs no samples and covers the whole repository. Then run both children over 0.8's sample set at the same commit, and diff the matched namespace, rule and offsets for each unit. Compare libmagic's mime type with `file -b --mime-type` on every sample too. Done when `docs/measurements/yara-compare.md` counts each kind of difference and says how many samples and rules the match half covered.
- [ ] **1.12 Triage.** Mark each difference as a yara-x incompatibility, recorded with its rule and the reason, or a port bug, fixed in `ace-yara`. Done when a rerun of 1.11 shows no unexplained difference.
- [ ] **1.13 Slowest-rule report.** Enable yara-x's `rules-profiling` feature behind a cargo feature that only the SVS build turns on, and print the slowest rules after a replay. Done when `cargo tree -e features` for the YARA pool binary doesn't show `rules-profiling`.

### Track B: results crate, SDK and test harness

- [x] **1.14 Observable kinds.** Dump ace3's observable type names (`ace3/saq/observables/`, with parents from `type_hierarchy.py`) to a JSON fixture, and define the Rust enum from it. Types are an enum, so nothing registers at import (#1030). Done when a test checks the enum against the fixture.
- [x] **1.15 Result envelope.** Define the record every result shares: analysis type name, schema version, details, summary, tags, and the observables and files it adds. Bytes stay bytes. A bytes field serializes to JSON as tagged base64 and never passes through a text codec (#999). Done when a non-UTF-8 byte string round-trips through JSON unchanged.
- [x] **1.16 Registry and schema export.** Register each analysis type by name and version, so finding a type's module needs no instance (#827). `ace schema export` writes each type's JSON Schema with `schemars`. Done when the export of a sample type is snapshot-tested.
- [x] **1.17 Validation.** Check a JSON result against its type's schema. Done when a result with an unknown field or a wrong type fails with the field's path in the error.
- [x] **1.18 Module traits.** In `ace-sdk`, define a sync trait for parsers and an async one for lookups. The task context gives the observable, the settings, the declared secrets, a cancellation token that blocking code can poll (#984, #986), and the time left (#845). A module can return a delay with a `run_after` and a timeout, the counterpart of `delay_analysis` (`ace3/saq/modules/base_module.py:685`). Done when an example module of each kind runs in a unit test.
- [x] **1.19 Manifest.** Each module crate exports a manifest: input observable types, output analysis type, the modules it depends on, resources, sandbox profile, settings schema and secrets. Settings deserialize with `deny_unknown_fields` (#858). Done when a settings block with an unknown key fails to load.
- [x] **1.20 HTTP client.** The SDK gives modules one HTTP client builder that always verifies certificates with rustls (#1018), sets a timeout on every call, and classifies "peer unavailable" errors in one place (#1096). Done when a test against a self-signed server fails and a refused connection is classified as unavailable.
- [ ] **1.21 File output.** The SDK writes a new file with its bytes, its name and path inside the alert, and its `yara_meta` tags, through a file store trait (a local directory until 2.5). Names from inside a file are untrusted, so the writer rejects absolute paths and `..` (#829). Done when writing `../../etc/passwd` fails and a normal file records its name, path, tags and sha256.
- [ ] **1.22 Spans.** The SDK runs each module call inside a `tracing` span with the root uuid, observable and module. Done when a log line from inside a module carries all three.
- [ ] **1.23 Test harness.** `ace-testkit` runs a module on a fixture observable or file without the core, checks the result against its schema, and snapshots it. Done when the example modules from 1.18 have snapshot tests.
- [ ] **1.24 Reference dumps.** A script in `tools/ace3/` runs one ace3 module on one sample in the `cli` analysis mode, inside ace3's dev container, and writes its analysis details as JSON. Phase 1 ports compare against these dumps. Done when it writes dumps for the five track C modules.

### Track C: five modules

- [ ] **1.25 Email headers.** Port the header and address part of `EmailAnalyzer` (`ace3/saq/modules/email/rfc822.py:979`) onto mail-parser, in `ace-mod-email`. Done when its output matches the reference dumps for ace3's email test fixtures, or each difference is listed and explained.
- [ ] **1.26 Email parts.** Add body parts and attachments as files. Keep ace3's output names, such as `.rfc822.headers`, and its `yara_meta` tags, such as `type=email.attachment`, because YARA rules match on both. Done when names and tags match the reference dumps.
- [ ] **1.27 RDAP.** Port `RdapAnalyzer` (`ace3/saq/modules/rdap.py:544`) as an async module on ICANN's RDAP client. Done when it matches the reference dumps against recorded HTTP responses for a domain and an IP address.
- [ ] **1.28 Delayed module.** Port the Splunk analyzer (`ace3/saq/modules/splunk.py`) with `BaseAPIAnalyzer`'s delay loop (`ace3/saq/modules/api_analysis.py:617-650`). It waits `correlation_delay` before the first query, returns a delay of `async_delay_seconds` while the query runs, and gives up at `query_timeout`. Done when a harness test against a recorded Splunk API sees a delay, then a result, and a timeout for a query that never finishes.
- [ ] **1.29 Archive extraction.** Port `ArchiveAnalyzer` (`ace3/saq/modules/file_analysis/archive.py:152`) onto the zip, sevenz-rust and flate2 crates, with RAR on the unrar crate, which binds RARLAB's C++ library, in-process inside the contained task. It runs `unzip`, `7z` and `unrar` today (`archive.py:278-451`). The unrar crate's C++ build counts in 1.31's numbers. Done when fixture archives (nested, password `infected`, a member named `../x`) give the same files, names and tags as the reference dumps.
- [ ] **1.30 YARA module.** Port `YaraScanner_v3_4` (`ace3/saq/modules/file_analysis/yara.py:171`) onto `ace-yara`, loading a ruleset from a path until 2.26. Done when a fixture file matches a fixture rule only when the right meta tags are passed.

### Decision

- [ ] **1.31 Build loop again.** Repeat 0.5's measurements on the real workspace. Done when `build-loop.md` shows them next to the spike's.
- [ ] **1.32 Language decision.** Write `docs/decisions/0001-language.md` from 1.12 and 1.31: keep Rust, or move the core to Go as DESIGN.md's *Alternatives considered* describes. The record says that 1.11 compared matches only on local samples. Done when the record is signed off. Phase 2 starts after that.

## Phase 2: the core, the queue and the bucket

The goal is to run the five phase 1 modules end to end from a submission.

### Storage

- [ ] **2.1 Postgres and MinIO.** Add both to Compose, published on ephemeral host ports. Done when `docker compose up postgres minio` is healthy while ace3's stack is running.
- [ ] **2.2 Migrations.** Add `ace-core` with SQL migration files and one Postgres schema per area. Commit sqlx's offline metadata in `.sqlx/`, and have CI run `cargo sqlx prepare --check` without a database. One function builds the connection pool for every component (#1023). Done when a query on a missing column fails the build.
- [ ] **2.3 Test databases.** Migrate and seed a template database once per test run, and give each test its own copy with `CREATE DATABASE ... TEMPLATE`. Done when tests run in parallel on separate databases.
- [ ] **2.4 Alert tree tables.** Roots, with an event time and where that time came from (#850). Observables, unique on (root, type, value). Results, unique on (root, observable, module), with the analysis type, schema version and JSONB details under a GIN index. Done when upserting one observable twice leaves one row.
- [ ] **2.5 Bucket.** `ace-store` puts and gets bytes by sha256 on S3 (MinIO in dev), with a size-capped cache on each node. A put also stores the libmagic mime type from 1.7. Carry over the pools and retention from `ace3/docs/CAS.md` and the `cas:` section of `ace3/etc/saq.default.yaml`. Done when two puts of the same bytes leave one object and a get on a second node fills that node's cache.

### Queue

- [ ] **2.6 Tasks and claims.** A task is (root, observable, module) with a state enum, `run_after`, lease owner and expiry, attempt count, error and input hashes. Workers claim with `FOR UPDATE SKIP LOCKED`. Done when two workers draining 1,000 tasks run each one exactly once.
- [ ] **2.7 Leases.** A worker renews its lease while it runs. A reaper requeues tasks whose lease expired and fails a task at its attempt limit. Done when killing a worker mid-task gets the task rerun after its lease expires.
- [ ] **2.8 Wakeups.** Workers wait on `LISTEN/NOTIFY`, with a bounded timeout as the fallback. Done when a test shows a task claimed without the fallback firing.
- [ ] **2.9 Delays.** A task whose `run_after` is in the future can't be claimed until then. Done when 1.28's delayed module runs again after its delay.
- [ ] **2.10 Eligibility.** When a result lands, in the same transaction, find the (observable, module) pairs that just became eligible. A module is eligible when it accepts the observable's type, the modules it depends on have results, the observable's directives allow it (such as `no_scan`), and the root's analysis mode includes one of the module's groups. Modes and module groups carry over from `ace3/etc/saq.default.yaml` (`module_group_*` from line 2537, `analysis_mode_*` from line 2749). When a root's mode changes, eligibility reruns over every observable the root already has. That happens when a detection turns a root into an alert in correlation mode (`ace3/saq/engine/analysis_orchestrator.py:394-398`). A cancelled dependency doesn't fail its dependents forever (#846). Done when a table-driven test covers each rule, and a detection mid-analysis queues the correlation group's modules for the observables already in the tree.
- [ ] **2.11 Root completion.** A root is complete when it has no queued, delayed or running tasks, and completion is one event that alert routing can wait for (#848). Done when a test sees exactly one completion event per analysis pass.
- [ ] **2.12 Cancellation.** Cancelling a root cancels its queued tasks and signals running ones through their cancellation token. Dispositioning an alert cancels it and then switches it to the `dispositioned` mode, which makes that mode's few modules eligible. Done when a running test module sees the cancel within one poll interval, and a dispositioned alert runs only `alert_added_to_event`.
- [ ] **2.13 Transactions.** Every write goes through a sqlx transaction value. `commit` consumes it and dropping it rolls back (#852, #1040). A retry helper reruns the whole transaction closure on a serialization failure, never part of it (#1084). Done when a test forces a serialization failure and the retry reruns every statement.

### Worker API

- [ ] **2.14 Lease API.** Axum endpoints for a worker to lease, renew, complete and fail tasks, and to get presigned bucket URLs for its inputs and outputs. A worker then holds neither database nor bucket credentials. Workers authenticate as their pool. Done when a worker with only an API token runs a task end to end.
- [ ] **2.15 Result writes.** Completing a task checks the result against its schema, stores it under its analysis type name, upserts its observables, records its files and queues what became eligible, all in one transaction. Done when an invalid result is rejected with the field's path and nothing from it is written.

### Pools

- [ ] **2.16 Async pool.** A pool's definition lists its modules, concurrency limit, sandbox profile and secrets, and its container sets the resource limits. `ace-pool` runs many async tasks in one process, up to the concurrency limit, which replaces the `network-semaphore` service. A panic in one task fails that task and the process keeps serving. Done when a pool with a limit of 4 never runs a fifth task while 50 are queued, and a panicking task leaves a failed row while the others finish.
- [ ] **2.17 Task supervisor.** For parser pools, a supervisor starts one process per task by exec, never fork (#982), sends the task on stdin and reads the result from stdout. Setup failures and module failures exit with different codes (#847). Done when a panicking parser leaves a failed-task row and the supervisor keeps leasing.
- [ ] **2.18 Containment.** Before the module runs, the task process sets rlimits on address space and CPU time, applies Landlock rules for files and TCP ports, and installs a seccomp filter that blocks fork, clone and exec. A process with no children dies completely when its PID is killed (#981). Done when test tasks that fork, exec, open a file outside their allowed paths, connect to a port that isn't allowed, or allocate past the limit are each stopped, and a task process reports one thread.
- [ ] **2.19 Hung tasks.** The supervisor kills a task process at its deadline and writes a failed-task row with the error and the input hashes. Done when an infinite-loop task is killed and its row names its inputs.
- [ ] **2.20 Replay.** `ace task replay <id>` fetches a failed task's inputs by hash and runs the module locally, outside containment, so a debugger can attach. Done when replaying 2.19's task reproduces the hang.
- [ ] **2.21 Bounded waits.** Wrap every network call, lock and join on a run or shutdown path in `tokio::time::timeout`. Shutdown stops leasing and releases held leases. Done when shutdown with a hung upstream finishes within its deadline and the hung task's lease is released.
- [ ] **2.22 Telemetry.** Export spans through OpenTelemetry, with the task id added to 1.22's identifiers. Done when one task's spans appear together in the collector.

### Config

- [ ] **2.23 Site overlay.** A small YAML overlay deserialized with `deny_unknown_fields`. A component with no section in it runs on its manifest's defaults (#1044). A module named in the overlay that no longer exists logs a warning, and startup continues (#901, #916). Done when tests cover an unknown key, a missing section and a removed module.
- [ ] **2.24 Secrets.** A process resolves only the secrets its pool's manifests declare (#1009). Done when a pool can't read a secret that only another pool declares, and its startup log lists only its own.

### YARA in the core

- [ ] **2.25 Ruleset builds.** A build task compiles the signatures repo at each new commit, puts the serialized ruleset in the bucket under its hash, and writes the manifest from 1.6 as a row (#1051). Done when a new commit produces a row that lists the files left out.
- [ ] **2.26 YARA pool.** The pool loads a ruleset by hash and switches to a new one only after it has loaded. Every match records its ruleset hash and commit. Done when a switch during a stream of scans drops none.
- [ ] **2.27 QA matches.** A match from a QA rule queues a task that records it. The file is already in the bucket, so there is no spool directory. Done when a QA match appears in the QA table and raises no alert.

### End to end

- [ ] **2.28 Submissions.** An endpoint that creates a root with its observables, files and analysis mode, and queues its first tasks. Done when a submitted file is in the bucket and its tasks are queued.
- [ ] **2.29 Compose stack.** `postgres`, `minio`, `ace`, a Rust parser pool and a network pool. Done when `docker compose up` brings every service up healthy while ace3's stack is running, and 0.6's check passes.
- [ ] **2.30 End-to-end test.** Submit an email with a domain in its headers and a zip attachment that a fixture YARA rule matches only through its `meta_tags`. Done when the email, archive, YARA, RDAP and delayed modules all have results, the root completes, killing the parser pool mid-run only delays completion, and the test runs in CI.

### Building outside this workspace

Site integrations live in their own repositories (decision 9), so this workspace has to be buildable from outside.

- [ ] **2.31 Extension points.** Add `ace-app`, which builds the `ace` binary and each pool binary from a list of crates, so another repository can build its own. Each thing an ace3 integration can add today (`ace3/docs/INTEGRATIONS.md`) becomes an entry in that list once its feature exists. That means analysis modules and collectors now, then API routes, alert toolbar buttons, alert page cards and analysis and manual-analysis templates in phase 5, hunt query sources and command types in phase 6, and alert routers in 7.13. Done when the open-source binaries are short `main` functions over `ace-app`, and a test builds a binary with one extra module.
- [ ] **2.32 site_ace workspace.** Start a site's Rust workspace as a new repository outside ace3's checkout, and leave the existing site_ace repository as it is. It depends on this workspace's crates by git tag, builds its own `ace` and pool images through `ace-app`, runs 0.4's layering check on its own crates, and follows *Running beside ace3*. Its CI also builds against this workspace's main branch, so a breaking change shows up before a tag. Done when a site's images pass 2.30's end-to-end test plus a test of one module of its own.

## Phase 3: comparison with ace3 on local samples

DESIGN.md's Sequence step 3 sends production traffic to both systems. For the proof of concept, both systems run 0.8's sample set on the laptop instead, and ace3 sends ace4 nothing. From here on, this comparison is the acceptance test for every module port.

- [ ] **3.1 Normal form.** A JSON form of an alert's tree that both systems can write: observables by (type, value), results by module, a fixed order, and no timestamps or absolute paths. Done when ace4 writes it for 2.30's root.
- [ ] **3.2 ace3 trees.** A script in `tools/ace3/` runs each sample through ace3's `cli` analysis mode in ace3's dev container and writes its tree in the same form. Done when both systems' forms of one sample agree on the five phase 1 modules.
- [ ] **3.3 Comparison command.** `ace compare` runs the sample set through ace4, diffs each tree against 3.2's output per module, skipping modules not yet ported, and writes the differences to a report. Done when it runs over the whole sample set.
- [ ] **3.4 Acceptance threshold.** Write down the threshold for accepting a port, such as no unexplained difference over the sample set. Done when the five phase 1 modules meet it.
- [ ] **3.5 Memory.** Measure each pool's private memory while 3.3 runs. ace3's figures come from production load: 365 to 491 MB on correlation workers, 597 to 1,028 MB on a busy email scanner, about 230 MB for a fresh worker, and 2.57 GB for `http-api-v2`'s 12 workers. Done when `docs/measurements/memory.md` has ace4's numbers and says what load they came from.

## Phase 4: libraries with no Rust equivalent

- [ ] **4.1 Python pool image.** Python with only the libraries that have no Rust equivalent: oletools 0.60.2, msoffcrypto-tool 6.0.0 and pcodedmp 1.2.6 (the pins in `ace3/installer/requirements-pinned.txt`), and XLMMacroDeobfuscator with xlrd2 and pyxlsb2, pinned to commits instead of the GitHub `master` archives that `ace3/Dockerfile:252` installs. A worker leases through the core API and is recycled after a task count or a memory limit. Done when a worker is recycled at its limit and the next task runs on its replacement.
- [ ] **4.2 Python results.** The core checks Python results against the JSON Schema exported in 1.16, as it does Rust results. Done when a Python result with a wrong field is rejected.
- [ ] **4.3 Stack dumps.** Before killing a hung Python task, the supervisor runs `py-spy dump` on it and stores the stacks in the failed-task row. The pool container gets ptrace permission on its own processes. Done when a hung test task's row holds its Python stack.
- [ ] **4.4 olevba.** Move `ace3/saq/modules/file_analysis/olevba.py` onto the Python pool. Done when 3.3's comparison accepts it.
- [ ] **4.5 rtfobj.** Move `ace3/saq/modules/file_analysis/rtf.py`, which runs oletools' rtfobj as a subprocess (`rtf.py:133`), onto the Python pool. Done when 3.3's comparison accepts it.
- [ ] **4.6 Office decryption.** Move `ace3/saq/modules/email/encryption/msoffice.py` onto the Python pool. Done when 3.3's comparison accepts it.
- [ ] **4.7 XLM and p-code.** Move `ace3/saq/modules/file_analysis/xlm.py`, which runs the `xlmdeobfuscator` command (`xlm.py:138`, `:161`), and `PCodeAnalyzer` in `vbs.py`, which runs pcodedmp through `ace3/bin/pcodedmp_wrapper`, onto the Python pool. Both call their library directly instead of a subprocess, and the task deadline replaces the wrapper's timeout. Done when 3.3's comparison accepts both.
- [ ] **4.8 Library diff command.** A command that runs a Python library and its Rust port over every file in 0.8's sample set and diffs their outputs. Done when it runs with the Python library on both sides and reports no difference.
- [ ] **4.9 PDF.** A Rust module on the qpdf crate's binding of libqpdf, in-process inside a contained task. It replaces pikepdf 10.17.0, which `ace3/saq/modules/file_analysis/pdf.py:139` uses to pull annotation URIs, form fields and JavaScript, AES-encrypted PDFs included, and the `pdf-parser.py` run at `pdf.py:84`. Check the crate's upkeep and its vendored libqpdf build first, and re-measure the build loop as in 0.5 once it links. Done when 4.8 shows no unexplained difference from pikepdf over the sample set's PDFs and 3.3's comparison accepts the module.
- [ ] **4.10 Port oletools.** Port the parts olevba and rtfobj use onto the cfb crate. Done when 4.8 shows no unexplained difference and the two modules move off the Python pool.
- [ ] **4.11 Port msoffcrypto.** Done when 4.8 shows no unexplained difference and 4.6's module moves off the Python pool.
- [ ] **4.12 Port pcodedmp and XLMMacroDeobfuscator.** Done when 4.8 shows no unexplained difference and 4.7's modules move off the Python pool.
- [ ] **4.13 Retire the Python pool.** Done when nothing runs on it and Compose no longer lists it.

## Phase 5: service layer, API and alert view

- [ ] **5.1 Actors.** One actor type in `ace-service` for users, API keys and internal callers (#1089, #953), carried by every write. Done when a test writes through the same function as each kind of actor.
- [ ] **5.2 Permissions.** Permission checks live in the service layer, with one case rule for storing and checking names (#831). Done when a mixed-case permission behaves the same when stored and when checked.
- [ ] **5.3 Audit.** One helper records the actor on each audited write (#830). Done when every write path in the service layer has an audit test.
- [ ] **5.4 Authentication.** GUI sessions and API keys. Done when both reach the service layer as an actor.
- [ ] **5.5 JSON API.** An axum adapter over the service layer, with its OpenAPI spec from utoipa. Start with the alerts, analysis and observables routers. The API keeps no `/api/v2` paths or payloads. Done when those endpoints have tests and appear in the spec.
- [ ] **5.6 The other routers.** One step per remaining router in `ace3/aceapi_v2/`: auth, crashes, detection, detection_points, email, events, file_collection, filter_screens, health, hunt, observable_comments, observable_types, remediation, response, saved_filters, search, secrets, svs, threat_types, threats, user_preferences, users and yara_qa. The `engine` router's download, upload and clear endpoints go away with the bucket and the root lock, and its `cli` endpoint becomes 5.12. The `nodes` router's drain and resume become stopping and starting a node's pools. Done per router when its endpoints have tests.
- [ ] **5.7 GUI base.** An askama base layout, with Datastar as one vendored file (ace3 vendors 1.0.4). Done when a template that uses a missing field fails the build.
- [ ] **5.8 Alert view.** Render an alert's tree from Postgres. When Postgres notifies of a new result, a Datastar server-sent event stream pushes it to the open page as an HTML fragment. Done when a test calls the view function directly, and a browser test sees a result appear on an open page without a reload.
- [ ] **5.9 Analysis templates.** Port the templates in `ace3/app/templates/analysis/` for the modules ported so far, such as `email_analysis.html`, `rdap.html` and `yara_analysis_v3_4.html`. Later ports bring their own. Done when each renders a fixture result.
- [ ] **5.10 Alert list.** Port `ace3/app/templates/analysis/manage.html` and its partials for filters, columns and refresh. Done when the list filters and pages through fixture alerts.
- [ ] **5.11 Other GUI areas.** One step per folder in `ace3/app/templates/`: admin, auth, events, file_collection, help, remediation, saved_filters, signatures and svs, plus `preferences.html`. Done per area when its views have tests.
- [ ] **5.12 GUI commands.** A command an analyst starts from the GUI (`ace3/docs/GUI_CLI.md`) runs as a task, contained like any other, whether or not the API stops it (#973). Done when closing the session leaves the command bounded by its task deadline.
- [ ] **5.13 Relationship graph.** One vendored client-side component, fed JSON from the API. Done when it renders 2.30's alert.
- [ ] **5.14 Analyst-edited lists.** Whitelists and suppressions live in Postgres behind the API, with an audit record (#1063), replacing file-watched settings (#1064) and `ace3/saq/whitelist.py`. Done when an edit through the API applies to the next task without a restart and its audit row names the actor.

## Phase 6: ingest

- [ ] **6.1 Journal email collector.** Port `ace3/integrations/site_ace/integrations/site_ace/src/site/collectors/journal_collector.py` into a site's Rust workspace (2.32). It long-polls a queue queue for S3 events and downloads each journaled email. It drops an email that a rule tagged `blacklist` matches, checked through `ace-yara` instead of yara-python. It submits the rest in email mode as alert type `mailbox`, with the S3 event time as the event time, the file named `email.rfc822`, and the directives `no_scan`, `original_email` and `archive`. Submissions are keyed by S3 object key, and a queue message stays on the queue after an AWS error. Done when a test against recorded queue and S3 responses drops a blacklisted email, submits a normal one, and submits a redelivered message only once.
- [ ] **6.2 Hunt loading.** Port `ace3/saq/collectors/hunter/loader.py` and `manager.py`. Hunts stay in the signatures repo, which has 328 files under `hunts/` in splunk, logscale, sentinel, rapid7, commands and scripts. Done when every hunt loads, or fails with the error ace3 gives it.
- [ ] **6.3 Hunt templates.** Render hunt templates with minijinja. Done when every template renders the same text as ace3's Jinja does from the same inputs.
- [ ] **6.4 Query hunts.** Port Splunk hunts first (`splunk_hunter.py`), then LogScale, Sentinel and Rapid7 as their clients land in 7.8. Done per source when a test against its recorded API makes the same submissions as ace3.
- [ ] **6.5 Suppression records.** The hunter writes a row for each suppression decision (#840). Done when a suppressed hit leaves a row.
- [ ] **6.6 Correlation hunts.** Port `ace3/saq/collectors/hunter/correlation/`. Done when the cases in `ace3/tests/saq/collectors/hunter/correlation/` pass as Rust tests.
- [ ] **6.7 Scheduler.** The tasks in `ace3/saq/cron_tasks.py` (see `ace3/docs/CRON.md`) move into the `ace` binary's scheduler. Done when each one has run once in a test.
- [ ] **6.8 Signatures check.** `ace signatures check` builds the ruleset from a signatures checkout with `ace-yara` and loads every hunt with 6.2's loader. Done when a rule that yara-x rejects makes the command fail.

## Phase 7: remaining modules, services and integrations

Port one pool at a time. Each module is done when 3.3's comparison accepts it and its analysis template exists.

- [ ] **7.1 Module inventory.** List the 90 `analysis_module_*` sections of `ace3/etc/saq.default.yaml` in `docs/modules.md`, with each module's pool, the libraries and tools it uses, the files it writes and the `yara_meta` tags it sets. a site's modules get the same inventory in its Rust workspace. Done when every module has a pool.
- [ ] **7.2 Reads through the API.** Workers never hold database credentials, so modules that query ACE's own database today, found by `get_db(` in `ace3/saq/modules/`, get read endpoints on the internal API. Done when the inventory names an endpoint for each.
- [ ] **7.3 External tools.** Phases 1 and 4 replace the archive tools, `pdf-parser.py`, `xlmdeobfuscator` and pcodedmp. ace3's modules also run `exiftool` (exif), `de4dot` (dotnet), `cfr` through `java` (java), and John the Ripper (`ace3/saq/cracking.py`) for encrypted archives and Office files. The inventory also checks `qrcode.py`, `vbs.py`, `js.py` and `pcap.py`, which mention subprocesses or the sandbox. Decide for each tool: a crate, the tool as its own task process, or ACE's sandbox runner (`ace3/saq/sandbox/`) for tools that start children. tshark stays in the sandbox runner. Done when the inventory records each decision.
- [ ] **7.4 Network pool.** Port the lookup modules the inventory places here, such as DNS on hickory-dns. Lookups that come from site_ace integrations, such as a mail API and LogScale, port in 7.8. Done per module.
- [ ] **7.5 Parser pool.** Port the file parsers in batches of related modules, using the crates DESIGN.md names (goblin and object, cfb, mail-parser) and 7.3's decisions. Start with `url_extraction`, which hits its 15-second cap on multi-line blobs today. Done per module, and for `url_extraction` when a multi-line blob that times out in ace3 finishes in under 15 seconds.
- [ ] **7.6 Tagging and detection.** Port the tagging and detection modules: `observable_modifier`, `user_defined_tagging`, `configuration_defined_tagging`, `site_tagger` and `observable_detection`. Done per module.
- [ ] **7.7 phishkit and js-deobfuscator.** Put both on the task queue as pools, replacing Celery, RabbitMQ and Redis (#1100). Their services keep their code. Done when 2.30's test gets `phishkit_analyzer` and `javascript_deobfuscation` results through the queue.
- [ ] **7.8 Integrations.** Port the integrations in the site_ace repository into a site's Rust workspace (2.32) one at a time: `ace_mail_api`, `ace_endpoint_vendor` (with LogScale), `ace_rapid7`, `ace_vt`, `ace_example_sandbox`, `ace_wiz` and `ace_intel_feed`. Microsoft and EndpointVendor publish no Rust SDK, so those clients are written from the API documentation. Splunk's client stays in this workspace. Every client uses 1.20's builder. Integration code that calls yara-python directly, such as 6.1's blacklist check, moves to `ace-yara`. Done per integration when its recorded-API tests pass and 3.3's comparison accepts its modules.
- [ ] **7.9 Remediation and file collection.** Remediation, the external remediation check and file collection become tasks on the one queue, not three copies of a queue-service scaffold (#894). A file collection that several alerts share belongs to each of them (#1101). Done when each runs from the queue in a test.
- [ ] **7.10 SVS.** Needs 7.14. Port `ace3/saq/svs/` with validation on `ace-yara`, replay from the bucket, and an event's SVS context ownership decided in one place (#842). Split it by `ace3/docs/SVS.md` when it starts. Done when the cases in `ace3/tests/saq/svs/` pass as Rust tests.
- [ ] **7.11 Search.** Index alerts with Postgres full-text search and pgvector. Port `ace3/tests/saq/search/test_retrieval.py` and run it against both this index and Qdrant. Done when `docs/decisions/` records whether Qdrant goes.
- [ ] **7.12 Monitoring.** Port the `monitoring` service (`ace3/saq/monitoring/`). Done when its checks run from the scheduler.
- [ ] **7.13 Alert routing.** Port `ace3/saq/alert_routing/`, which decides which queue an alert belongs in and which integrations extend with their own routers. It runs on 2.11's completion event (#848). Done when the cases in `ace3/tests/saq/alert_routing/` pass as Rust tests.
- [ ] **7.14 Detection verdicts.** Port `ace3/saq/detection_verdicts/`, which SVS reads for inherited labels (`ace3/saq/svs/yara/diff.py`). Done when the cases in `ace3/tests/saq/detection_verdicts/` pass as Rust tests.
- [ ] **7.15 AI query.** Port `ace3/saq/ai_query/`, served today by `ace3/aceapi_ai/` and the `http-api-ai` service. Done when its endpoints have tests.

## Deferred

These wait until there's a decision to take ace4 past a proof of concept, and each gets its own plan then.

- **Production traffic.** DESIGN.md's shadow mode: ace3 forwards submissions to ace4, and a job compares the trees alert by alert, with modules that act outside ace4 (remediation, `email_archiver`, `alert_added_to_event`, SVS sample capture) turned off.
- **The SVS corpus.** DESIGN.md's YARA comparison and library checks over every SVS sample. The samples live in production, not on the laptop.
- **Data from ace3.** Moving users, whitelists, events, alerts, the observable index and SVS labels, and deciding what happens to old alerts.
- **Clients of ace3's API.** A client generated from the OpenAPI spec to replace `ace3/ace_api.py`, and moving its callers onto it.
- **The signatures repository.** Running 6.8's check in its CI, and fixing the yara-x incompatibilities 1.12 records.
- **Production deployment.** The production Compose file with S3, `replicas` per pool, `fluent-bit` and TLS. Multi-node stacks and draining a node. Memory under production load.
- **Cutover.** Checking off DESIGN.md's *What it replaces* table.

## Decisions

Made on 2026-10-29, where DESIGN.md left a gap or didn't match ace3.

1. **Analysis modes stay.** A root carries a mode that names its module groups, and a mode change reruns eligibility. DESIGN.md doesn't mention modes. (2.10, 2.12)
2. **Email comes in through a site's journal collector.** ace3 removed its own email collectors in October (`b6e03230`, `754619c6`), so the collector DESIGN.md names is the one in the site_ace integration. (6.1)
3. **extract_msg is dropped.** It has never been in ace3's history. Outlook `.msg` support would be new work.
4. **RAR uses the unrar crate,** in-process inside the contained task. (1.29)
5. **ace4 is a laptop proof of concept for now.** ace3 sends it nothing. Moving data, production traffic and cutover wait until there's a decision to go further. (*Scope*, *Deferred*)
6. **PDFs go through libqpdf.** ace3 never runs qpdf itself; it uses pikepdf, which wraps libqpdf. A Rust module on the qpdf crate replaces pikepdf and `pdf-parser.py`. (4.9)
7. **The API is new.** It keeps no `/api/v2` compatibility. (5.5)
8. **pcodedmp and XLMMacroDeobfuscator go on the Python pool,** pinned, until their ports match. (4.1, 4.7, 4.12)
9. **Site integrations live in their own repositories.** site_ace is already its own repository, cloned into `ace3/integrations/` and ignored by ace3's git. Its Rust workspace builds its own `ace` and pool images from this workspace's crates, pinned by tag. ace3 loads integrations as Python packages at run time (#1031); here they are crates linked at build time. (2.31, 2.32, 6.1, 7.8)
10. **Alert routing, detection verdicts and AI query get steps.** DESIGN.md doesn't mention them, but ace3 has them. (7.13, 7.14, 7.15)
11. **ace4's stack runs beside ace3's on one machine.** It takes its own project name, `ACE4_` variables, one fixed host port that ace3 doesn't use, and `ace4-*` image names. (*Running beside ace3*, 0.6, 2.1, 2.29)
12. **Samples come from the laptop.** The local ace3 has no SVS corpus, so the comparisons use ace3's test fixtures and files added by hand. The YARA check compiles the whole signatures repo with both scanners and compares matches only on those files. (0.8, 1.11, 3.3, 4.8)
13. **Other repositories don't change.** Scripts that need ace3's code live in `tools/ace3/` and run in ace3's dev container. The signatures and site_ace repositories stay as they are. (1.9, 1.10, 1.24, 2.32, 3.2)

## Not in this plan

DESIGN.md's *Without a rewrite* lists three changes to make in ace3 itself. They belong in ace3's tracker.

## Design flaws by step

| Issue | Title | Step |
|---|---|---|
| #982 | ACE forks threaded processes | 2.17 |
| #984 | Modules get no stop signal for blocking calls | 1.18 |
| #1029 | Loading an alert imports every analyzer in it | 0.4 |
| #1030 | Observable types register on import | 1.14 |
| #1031 | Every process imports every integration | 0.4, 2.31 |
| #1032 | Observable types register GUI actions at import | 5.9 |
| #1066 | `saq/modules/email/__init__.py` imports every submodule | 0.4 |
| #843 | Presenter imports aceapi_v2, a cycle | 0.4 |
| #953 | The credential type lives in aceapi_v2 | 5.1 |
| #999 | Details encode bytes lossily | 1.15 |
| #827 | Mapping an analysis to its module needs an instance | 1.16 |
| #850 | `event_time` has no provenance | 2.4 |
| #848 | Routers can't tell an analysis pass is final | 2.11 |
| #1101 | A shared file collection belongs to one alert | 7.9 |
| #1009 | Every process resolves every `env:` reference | 2.24 |
| #1044 | `get_service_config()` raises for an unconfigured service | 2.23 |
| #916 | A removed module in a mode or group stops every worker | 2.23 |
| #901 | A site overlay of a removed module is fatal | 2.23 |
| #858 | Module configs ignore undeclared keys | 1.19 |
| #1063 | No shared mechanism for analyst-edited settings | 5.14 |
| #1064 | FileWatcher skips a missing file | 5.14 |
| #1040 | ORM session and cursor helpers hold separate connections | 2.13 |
| #852 | A failed commit leaves the session unusable | 2.13 |
| #1084 | Retry reruns only its own statements | 2.13 |
| #1023 | The GUI's engine is built outside the pool | 2.2 |
| #981 | Containment uses process groups, which don't nest | 2.18 |
| #973 | A GUI CLI run is contained only by its session | 5.12 |
| #986 | Cancel never reaches the module | 1.18, 2.12 |
| #846 | A cancelled dependency fails its dependents forever | 2.10 |
| #845 | Modules can't ask how much time they have left | 1.18 |
| #847 | Sandbox launcher uses one exit code for setup failures and verdicts | 2.17 |
| #1089 | No actor type for internal callers | 5.1 |
| #830 | No shared audit helper | 5.3 |
| #831 | Permissions stored and enforced with different case rules | 5.2 |
| #894 | Three copies of one queue-service scaffold | 7.9 |
| #842 | SVS context ownership derived separately by each caller | 7.10 |
| #840 | Hunter suppression decisions aren't recorded | 6.5 |
| #829 | No guarded API for writing a file from an untrusted name | 1.21 |
| #1051 | yara_scanner keeps no record of what it compiled | 1.6, 2.25 |
| #1100 | Celery managers hardcode their broker | 7.7 |
| #1018 | ace_api disables TLS verification | 1.20 |
| #1096 | `log_peer_unavailable` only knows stdlib errors | 1.20 |
| #920 | `initialize_environment` ignores `saq_home` | 0.7 |
