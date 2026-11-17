# What a task process costs at its start, and the tasks that store nothing

`compare-speed.md` found that a parser or sandbox task process built every module of its pool before it ran one, and left it. This is that step: what the cost was, the change, both measurements, and a design for the next thing the same numbers point at, which is not built.

Measured on 2026-11-17 on one machine: Docker (Rancher Desktop) with 10 CPUs and 31 GiB, ace3's stack idle on the same VM, release images, the e2e stack's one-rule ruleset and overlay (`tests/e2e/site`). "HEAD" is `4734344e`, before this change. A run of the comparison is the whole sample set: 472 samples and 232,927 tasks in every run here, which at HEAD were 150,252 parser and 55,662 sandbox task processes.

## What a task process did at its start

`<binary> task --overlay PATH --rulesets DIR`, started by the supervisor for every task with an empty environment, did this before it read its task:

1. read and parsed the site overlay;
2. made the pool's components from it, which checks every module's settings block;
3. resolved the secrets every module of the pool declares (none for the open-source parsers);
4. built every component: its settings loaded again, then `Module::init`;
5. read the task from stdin, found its module among those built, contained itself and ran it.

The supervisor had already done 1 to 4 once, when the pool started.

**Where the time went.** A release build of this change with a temporary mode that ran steps 1 to 4 as HEAD did and printed each one's time (`<binary> task --phases`, removed again), 100 starts of each pool's binary in the dev container, each a new process. Microseconds, median and range:

| Phase | Parser pool, 53 modules built | Sandbox pool, 16 modules built |
|---|---|---|
| CPU before the task mode is reached: the loader, the binary's list of pools | 1,958 (1,250 to 15,772) | 1,824 (1,197 to 11,399) |
| Overlay: read | 350 (265 to 938) | 370 (272 to 816) |
| Overlay: parse | 339 (300 to 950) | 333 (295 to 758) |
| Components, with every settings block checked | 48 (40 to 566) | 13 (10 to 401) |
| Secrets | 3 (2 to 41) | 3 (1 to 11) |
| Every module built | 20,730 (17,917 to 31,214) | 13,751 (11,852 to 18,626) |
| Every module dropped again | 586 (494 to 961) | 600 (496 to 843) |
| Steps 1 to 4 and the drop | 22,052 (19,393 to 33,927) | 15,113 (13,088 to 19,929) |

The parser pool links 55 modules, and two of them are off unless the overlay turns them on (`ssdeep`, `email_conversation_link_analyzer`). So the cost is `init`, not settings or the overlay, and nearly all of it is a few modules:

| Module | Its `init`, microseconds | What it does there |
|---|---|---|
| `ioc_extraction` (parsers) | 11,863 (10,160 to 14,334) | compiles its indicator patterns and reads libmagic's database |
| `url_extraction` (parsers) | 2,034 (1,761 to 8,230) | reads libmagic's database, 10.4 MB |
| `phishkit_analyzer` (parsers) | 1,571 (1,227 to 2,520) | reads libmagic's database |
| `file_type` (parsers) | 1,555 (1,207 to 2,299) | reads libmagic's database |
| `protected_url_analyzer` (parsers) | 1,502 (1,241 to 2,546) | reads libmagic's database |
| `yara_scanner_v3_4` (parsers) | 1,364 (1,157 to 2,317) | loads the current ruleset, one rule here |
| `lure_url_analyzer` (parsers) | 270 (216 to 582) | compiles a pattern |
| `site_tagger` (parsers) | 48 (36 to 73) | reads its rows |
| the other 45 parsers built | 43 in all, none over 16 | |
| `ocr` (sandbox) | 8,172 (6,964 to 10,795) | reads its dictionary |
| `de4dot` (sandbox) | 2,056 (1,742 to 2,483) | reads libmagic's database |
| `cve_2021_30657_analyzer` (sandbox) | 1,555 (1,291 to 2,631) | reads libmagic's database, compiles a pattern |
| `ilspy` (sandbox) | 1,481 (1,236 to 2,833) | reads libmagic's database |
| `qrcode`, `upx` (sandbox) | 124 and 102 | OpenCV's thread setting, a pattern |
| the other 10 sandbox modules | 16 in all | |

`ioc_extraction` and `ocr` need a directive that no sample of the comparison has, so no task of either ran in a comparison, yet every parser task paid for `ioc_extraction` and every sandbox task for `ocr`. For a task of a module that builds nothing, which is most tasks, all 20.7 ms and 13.8 ms of building went to modules that weren't its own. With a production ruleset the YARA module's share is far larger: `memory.md` measured 77 ms more a task with the signatures' ruleset, paid then by every parser task and now by YARA tasks only.

What these numbers could be measuring instead: they are in one process, one module after another, so a module that reads a file another read just before finds it in the page cache; the dev container is not the pool's image, though the build is of the same sources and profile; and the overlay is read from a bind mount of the Mac's disk, as it is in the stack. The sum of the medians (20,250 and 13,506) is within 3% of the whole, so no module's cost hides in another's.

**The whole task process, on the pools' own images.** `tools/task-start/measure` starts the task mode 100 times in each of three forms in a container made from the pool's image, with an empty environment: `process`, an argument the mode refuses, which is the process alone; `built`, a task whose output directory can't be made, so the process ends once its modules are built and its task is read; and `whole`, a task on a 74-byte text file run to its end. Three series each at HEAD, 300 starts, milliseconds, median and range, with the three series' medians:

| Form at HEAD | Parser pool | Sandbox pool |
|---|---|---|
| `process` | 3.03 (2.43 to 5.07); 3.05, 3.06, 2.98 | 2.75 (2.13 to 6.01); 2.77, 2.82, 2.67 |
| `built`, any module | 24.61 (21.73 to 31.65) `file_type`; 25.06 (22.13 to 54.52) `email_analyzer`; 24.68 (22.04 to 33.04) `yara_scanner_v3_4` | 18.14 (15.47 to 24.14) `archive`; 17.70 (15.42 to 24.00) `ocr`; 17.26 (15.24 to 22.91) `exif` |
| `whole`, declined | 25.25 (22.19 to 50.13) `email_analyzer`; 25.76 (22.46 to 38.76) `yara_scanner_v3_4` | 18.07 (15.44 to 25.07) `archive`; 18.45 (15.68 to 50.06) `ocr`; 18.03 (15.56 to 25.06) `exif` |
| `whole`, with a result | 29.02 (26.25 to 41.98) `file_type` | |

That confirms `compare-speed.md`'s 22.5 ms and 15.5 ms, which are near these runs' fastest starts: 22 ms of a parser task and 15 ms of a sandbox task were spent before the task was read. These include bash starting and reaping the process, which `process` measures alone, and leave out what the supervisor does for a task.

```sh
# RULESETS is the parser pool's ruleset directory, copied out of a stack the comparison left up:
# docker cp ace4-e2e-parsers-1:/var/lib/ace4/rulesets RULESETS
# at HEAD, whose task mode takes the overlay and the ruleset directory as arguments
tools/task-start/measure ace4-parsers:latest ace-parsers file_type email_analyzer yara_scanner_v3_4 \
    --rulesets RULESETS --head-request --task-arg=--overlay --task-arg=/etc/ace4/overlay.yaml \
    --task-arg=--rulesets --task-arg=/var/lib/ace4/rulesets
tools/task-start/measure ace4-sandbox:latest ace-sandbox archive ocr exif \
    --head-request --task-arg=--overlay --task-arg=/etc/ace4/overlay.yaml
# on this change
tools/task-start/measure ace4-parsers:latest ace-parsers file_type email_analyzer yara_scanner_v3_4 \
    url_extraction phishkit_analyzer protected_url_analyzer ioc_extraction lure_url_analyzer site_tagger \
    --rulesets RULESETS --settings 'yara_scanner_v3_4={"rulesets": "/var/lib/ace4/rulesets"}'
tools/task-start/measure ace4-sandbox:latest ace-sandbox archive ocr exif de4dot ilspy \
    cve_2021_30657_analyzer qrcode upx
```

On this change the modules run on their defaults, where the e2e overlay has settings for two of them. `phishkit_analyzer`'s `init` doesn't read its settings, and `site_tagger`'s reads the overlay's two rows in 48 microseconds.

## What it does now

`<binary> task [--overlay PATH]` reads its task first, because the task names the module, and builds that one module:

1. reads the request from stdin, which now carries the module's own name (`module`; `task.module` is an instance's name for a named instance) and the settings block the supervisor built that module from (`settings`);
2. resolves the secrets that one module declares, which opens the overlay only if it declares any;
3. builds the module: its settings loaded from the request's block, then `Module::init`;
4. contains itself and runs the module, as before.

It reads no overlay, checks no other module's settings and builds no other module. The ruleset directory is no longer an argument, because the YARA module's block in the request holds it.

**What a pool refuses at its start is the same, and is checked there only.** The supervisor still reads the overlay and builds every module once, before it leases anything (`parser_modules` in `crates/ace-app/src/pools.rs`), and the pool stops there with the module's name on a settings key the module hasn't (#858), a value of the wrong type, an instance with a bad name, a clashing name or an input its module doesn't take, settings for a module that runs only as instances, a module whose `init` fails on its settings, or a module that runs a tool the pool doesn't carry. A section for a module the binary hasn't is skipped (#901, #916), and a module with no section runs on its defaults (#1044). None of that changed. What changed is that a task process used to repeat all of it on every task and no longer does any of it, so the check now happens once, where PLAN.md 2.23 puts it.

A task then runs on the overlay as it was when the pool started. Before, a task process read the overlay again on each task while its supervisor kept its first reading, so an overlay edited under a running pool reached tasks half-way, and a mistake in it failed every task of the pool with a setup error, hours after the start. Now an edit takes a restart of the pool, as it always has for a network pool, and a mistake stops the pool at that restart.

The one failure still left to a task's setup is its own module's `init` failing on something that changed since the start, such as a file it reads having gone. It fails that task with the module's name, and no longer fails every other module's tasks with it.

**Containment.** Nothing moved across it. The module is still built before the process contains itself, so its `init` can read what the contained process can't, and it is still contained before the module sees the task's input. The request was always read and parsed before containment; it is now read before the module is built instead of after. `Module::init` takes the module's settings and nothing else, so nothing from the task reaches it, and the settings are the supervisor's, from its own reading of the overlay. Nothing a module builds moved into the supervisor: it built every module at its start before and does now.

**Secrets.** A task process used to resolve the secrets of every module of its pool and hand the whole set to each module's entry, where a module could read only the names it declares. It now resolves the declared secrets of its own module alone, so it holds fewer and no module can read more than before. A task process has no environment, so a secret the overlay reads from a variable was never set for it, and one the overlay reads from a file was and still is, if the task's user can read the file. No open-source parser declares a secret.

**Lookup pools** don't have this cost in any form. A network pool is one process that builds its modules once, when it starts, and runs every task in it. Nothing there changed.

**Site binaries** need no change. `ParserPool`, `LookupPool` and `App::pool_main` are as they were, and a site's parser is built in its task process through the same registry as the open-source ones. `crates/ace-site-example` now has a parser of its own and an `example-parsers` binary to show it.

The tests:

| What | Test |
|---|---|
| Each refusal above stops the pool at its start, with the module's name | `ace-app`: `a_setting_that_does_not_load_stops_the_pool_at_its_start`, `a_module_that_does_not_build_stops_the_pool_at_its_start`, `an_instance_the_overlay_may_not_declare_stops_the_pool_at_its_start`, `a_module_whose_tool_the_pool_lacks_stops_the_pool_at_its_start` |
| A missing section and a removed module don't | `ace-app`: `a_missing_section_and_a_removed_module_do_not_stop_the_pool` |
| The same, through a site's real binary and real modules, before it looks for a lease API | `ace-site-example`: `a_site_s_parser_pool_refuses_a_bad_setting_when_it_starts` |
| A task process gets the block its module was built from | `ace-app`: `a_task_process_gets_the_block_its_module_was_built_from_at_the_start` |
| A task process builds only its task's module: with the YARA rules removed under a running pool, another module's task still runs and a YARA task fails its setup | `ace-pool`: `a_task_process_builds_only_its_tasks_module` |
| A site's parser is built alone from its request, contained, and its `init`'s refusal fails the task's setup | `ace-site-example`: `a_site_s_parser_is_built_alone_in_its_task_process` |
| A task process resolves only its own module's secrets | `ace-app`: `a_task_process_resolves_only_its_own_modules_secrets` |

`ace-pool`'s own test pool builds its task processes the same way now, so its containment, deadline, tool and YARA tests run on this path.

## Before and after

**The task process**, `tools/task-start/measure` on each pool's image as above, three series of 100 at HEAD and three on this change, milliseconds, median and range of the 300:

| Form | HEAD | This change |
|---|---|---|
| parsers, `process` | 3.03 (2.43 to 5.07) | 3.04 (2.30 to 4.43) |
| parsers, `email_analyzer` built | 25.06 (22.13 to 54.52) | 3.06 (2.45 to 4.54) |
| parsers, `email_analyzer` whole, declined | 25.25 (22.19 to 50.13) | 3.33 (2.57 to 4.61) |
| parsers, `file_type` built | 24.61 (21.73 to 31.65) | 5.25 (4.32 to 9.06) |
| parsers, `file_type` whole, with its result | 29.02 (26.25 to 41.98) | 10.22 (9.09 to 17.45) |
| parsers, `yara_scanner_v3_4` built | 24.68 (22.04 to 33.04) | 6.02 (4.60 to 8.65) |
| parsers, `yara_scanner_v3_4` whole, no match | 25.76 (22.46 to 38.76) | 6.38 (5.08 to 32.66) |
| sandbox, `process` | 2.75 (2.13 to 6.01) | 3.16 (2.42 to 5.55) |
| sandbox, `archive` built | 18.14 (15.47 to 24.14) | 3.32 (2.61 to 5.10) |
| sandbox, `archive` whole, declined | 18.07 (15.44 to 25.07) | 3.58 (2.58 to 7.97) |
| sandbox, `exif` whole, declined | 18.03 (15.56 to 25.06) | 3.56 (2.80 to 5.24) |
| sandbox, `ocr` whole, declined | 18.45 (15.68 to 50.06) | 12.85 (11.07 to 18.87) |

The series' medians differ by up to 0.6 ms between series, so a difference under a millisecond between two rows says nothing: `archive` built reads above its whole task at HEAD. A module that builds something still pays for it, and only for it, on its own tasks. On this change, whole and declined unless said: `url_extraction` 5.52 (4.67 to 26.51), `phishkit_analyzer` 5.37 (4.46 to 10.95), `protected_url_analyzer` 5.45 (4.59 to 10.03, with its result), `lure_url_analyzer` 4.04 (2.96 to 20.99), `site_tagger` 3.49 (2.63 to 6.43), `ioc_extraction` 18.64 (16.79 to 28.73, with its result), `de4dot` 5.28 (4.50 to 7.66), `ilspy` 5.21 (4.52 to 7.52), `cve_2021_30657_analyzer` 5.56 (4.68 to 8.57), `qrcode` 3.41 (2.77 to 6.60), `upx` 3.53 (2.88 to 7.32).

**What a task's floor is made of now.** A declined task of a module that builds nothing takes 3.3 ms in the parser pool and 3.6 ms in the sandbox pool, against 3.0 and 3.2 for the process alone. So the floor is the process: about 2 ms of CPU before the task mode is reached (the loader on a 105 MB binary with nine shared libraries, and the binary building its list of pools, which wasn't split further), the rest bash starting and reaping it. Reading the request, containment (the rlimits, Landlock and seccomp), the module declining and the reply are 0.3 ms together.

**The comparison**, `tests/e2e/run --compare --keep`, one run at HEAD and one on this change, the same day, each on a new stack with 8 samples at once and 8 slots, with a script reading every container's cgroup `cpu.stat` every 5 to 8 seconds for the CPU figures (a `docker exec` a container a tick, on both runs). The CPU is from the last reading before `ace compare` started to the first after it ended.

| | HEAD | This change |
|---|---:|---:|
| `ace compare`, seconds | 1,419.6 | 1,377.2 |
| A sample: median (range), seconds | 18.67 (2.04 to 108.95) | 14.12 (1.28 to 100.19) |
| CPU seconds, all containers | 9,050 | 4,448 |
| parsers | 4,856 | 1,110 |
| sandbox | 1,755 | 660 |
| Postgres | 1,464 | 1,557 |
| the core | 704 | 832 |
| bucket | 230 | 247 |
| lookups, scanners, the AI API | 40 | 42 |
| Cores busy on average | 6.38 | 3.23 |
| Parser task processes | 150,252 | 150,276 |
| Sandbox task processes | 55,662 | 55,662 |

- **The stack does the same work on half the CPU**: 4,601 core-seconds less, 51%. The two pools lost 4,841, which is more than the phase timing predicts (150,252 parser tasks at 22.0 ms and 55,662 sandbox tasks at 15.1 ms are 4,150, less the 40 or so that tasks still spend on their own modules): eight task processes at once, each reading libmagic's database three or four times, cost each other more than one alone does. Postgres and the core used 221 more, which one run each can't tell from noise.
- **The run is 3% shorter, not half.** The median sample is 24% shorter and the sum of the samples' times 3%, and some samples took longer than at HEAD (`ace4/office/xlm_branch_err_*.xlsm`, five samples, 28 to 33 s at HEAD and 79 to 91 s here). A sample's time with eight in the stack is mostly its wait for the others' tasks, so one sample's time isn't comparable between runs. What bounds the whole run is in the next section.
- **The 24 more parser task processes** are tasks that asked for a delay once more, which follows the timing.
- **One run of each, and a second pair without the sampler.** `tests/e2e/run` whole, which runs the same comparison with nothing sampling it: the director's run at HEAD earlier the same day took 1,222.9 s for the comparison (median sample 15.75 s, 2.04 to 97.59), and this change's took 1,063.9 s (12.85 s, 1.28 to 90.79), 13% less. So the runs with the sampler were 16% and 29% longer than the runs without it on the same code, which is more than the change itself moves a run, and what else the machine did differed too. The CPU figures are the ones to read. The wall times say the run got somewhat shorter, 3% in one pair and 13% in the other, and not by how much.

**The same report.** The four reports (the director's and the sampled one at HEAD, the sampled one and `tests/e2e/run`'s on this change) were compared pair by pair as `compare-speed.md`'s *The same report* does, setting aside seconds, roots, hashes, times and temporary directories. Every pair has the same samples in the same order, none absent or failed, the threshold met (0 unexplained, 378 harness, 0 unported, no stale row), the same rows, and for every sample the same differences by module, class and path with the same values, except the redirection of pdftotext's text, which follows the Ghostscript rewrite's hash: the coin toss that doc describes. It differs in 21 to 25 samples between a run at HEAD and a run on this change, in 22 between the two runs at HEAD and in 26 between the two on this change, and nothing else differs in any pair. Explained differences: 7,883 and 7,889 at HEAD, 7,893 and 7,886 here.

## What bounds a run now: a pool leases one task a request

Found here and left. A pool's lease loop takes a free slot, asks the core for one task, starts it and asks again (`lease_loop` in `crates/ace-pool/src/pool.rs`), so a pool starts tasks no faster than one lease request after another, however many slots it has. With a task process at 25 ms that hid behind the slots. At 3 ms it is the limit.

On the stack the comparison left up, 14 of the larger samples were run again with 8 at once while `psql \watch 0.1` counted the queue's tasks by state and lease owner:

| Parser and sandbox slots | The 14 samples | Tasks a second | While over 50 tasks were due: parser tasks running, median (mean, most) | sandbox | Tasks due, median |
|---:|---:|---:|---|---|---:|
| 8 | 133.1 s | 140 | 2 (1.90, 7) | 1 (1.02, 7) | 1,400 |
| 16 | 122.1 s | 152 | 2 (1.74, 5) | 1 (0.99, 7) | 1,556 |

18,578 tasks each time, one run each. With some 1,400 tasks waiting, the parser pool had 2 of its slots busy at the median and the sandbox pool 1, and doubling the slots changed neither. Over the whole comparison the parser pool started 109 tasks a second, 9 ms a task, which is the time of a lease request and not of a task. What this could be instead: the sampler sees a moment every 100 ms and a task now lasts a few milliseconds, so it undercounts short tasks, though not by the factor between 2 and 8; and the core or Postgres could be what makes a lease take 9 ms, which wasn't looked at (Postgres used 1.1 cores and the core 0.6 of the machine's 10).

Leasing several tasks a request, or keeping several requests in flight, would be a small change to the lease loop and the lease API, with nothing to do with containment. It wasn't made, because it changes how a pool takes work and wasn't this step. Until it is, the wall time of a run follows the number of tasks the parser pool has to lease, which is the other reason the next section matters.

## The tasks that store nothing: a design, not built

85.8% of a comparison's tasks end without a result: 199,921 of 232,927. A module is started on an observable only to decide it has nothing to do there, and for a parser that is a process, a download of the file, a row in the queue, a lease and an end. Nothing here is built. It is what decides those tasks today, what a cheaper decision could remove, and what each way of making it risks.

### What decides today

The core decides before it queues a task (`ace_core::eligibility::check`): the observable's type against the component's inputs, the root's analysis mode or an observable modifier's limit, a whitelisted observable, the directives that keep a module off (`SKIP_DIRECTIVES`, `exclude_all`), the directives it requires (`REQUIRED_DIRECTIVES`, `REQUIRED_DIRECTIVES_BY_KIND`), the observable's own exclusions, and the modules it depends on having a result. That is ace3's `accepts()`: its `valid_observable_types`, `required_directives`, exclusions and limited analysis. ace3's `accepts()` also has `required_tags`, `requires_detection_path`, `valid_queues`, `invalid_queues`, `invalid_alert_types` and `file_size_limit`, which ace4's core hasn't; ace3's shipped configuration sets only `file_size_limit`, on five modules, and ace4's modules check that themselves.

Everything else is decided inside the module, in ace4 and in ace3 alike: whether the file is a PDF, an archive, an email, named `.dmg`, an output of another module. ace3 pays almost nothing for it, because its modules run one after another in one Python process. ace4 pays a task for it.

### What decides each of the 199,921

From the baseline run at HEAD, by `tools/task-start/declines`: every task's row with whether its module stored a result (`queue.tasks` joined to `analysis.results`), and the reason of every skip, which the core logs with the task's id (199,449 lines; the other 472 are the core's own hooks task, one a root). Each reason was read against its module's code and put in one class, by the first check that declined; the script holds that reading as a list of rules and prints any reason it has no rule for. One run; the counts of tasks are the same in every run.

| Pool | Tasks | Stored a result | Stored nothing |
|---|---:|---:|---:|
| parsers | 150,098 | 11,240 | 138,858 |
| sandbox | 55,662 | 1,399 | 54,263 |
| lookups | 26,695 | 20,367 | 6,328 |
| the core's hooks | 472 | 0 | 472 |
| all | 232,927 | 33,006 | 199,921 |

The comparison stored 34,290 results. The other 1,284 are under a module's name that has no task of that name: the core's hooks store theirs under one task a root.

| What decided the task that stored nothing | parsers | sandbox | lookups | all | Share |
|---|---:|---:|---:|---:|---:|
| The file's name or path: `.dmg`, `.img`, `.vbs`, `.js`, `document.xml.rels`, an MHTML extension, another module's output, `file_hash_analyzer`'s ignore patterns | 18,021 | 8,874 | 4,066 | 30,961 | 15.5% |
| `file_type`'s result, which the module waits for: not an email, not HTML, not an Office file, not a certificate | 14,830 | | | 14,830 | 7.4% |
| The observable's type, given the module's settings: `site_tagger` has no row for that type | 8,537 | | | 8,537 | 4.3% |
| Which module added the file: not `officeparser3`'s or `rtfole`'s output | 6,575 | | | 6,575 | 3.3% |
| The file's directives, the mode and its name: `phishkit_analyzer` | 3,689 | | | 3,689 | 1.8% |
| The root's tree: no email in the root | 3,038 | | | 3,038 | 1.5% |
| The file's size: empty, or over a limit | 323 | 40 | | 363 | 0.2% |
| **Facts the core holds when it queues the task** | **55,013** | **8,914** | **4,066** | **67,993** | **34.0%** |
| **The first bytes of the file**: a magic number, `%PDF` or `<?xml` in the first kilobyte, libmagic's answer | **54,213** | **45,050** | | **99,263** | **49.7%** |
| **A parse or a scan of the whole file**: no YARA rule matched, no Excel 4.0 macro, no MIME boundary, no data URL, not encrypted | **28,277** | **299** | | **28,576** | **14.3%** |
| An observable's value: not in a list, not routable, one spelling | 1,355 | | 2,262 | 3,617 | 1.8% |
| The core's hooks task | | | | 472 | 0.2% |

Of the 99,263 decided by the first bytes, about 69,000 compare fixed bytes at a fixed place or search the first kilobyte for a marker (the Java, PE, PDF, XML, shortcut, RTF, OLE, pcap, OneNote and script-encoding checks). The other 30,000 ask libmagic or read some structure (`de4dot`, `ilspy`, `qrcode`, `archive`, `autoit`, `tls_keylog`, `rar_encryption_analyzer`, `exif`).

What this could be miscounting: a module that checks two things is counted under the first that declined, so a task counted under a name might also have failed a magic check; the classes are one reading of 60 modules' code, not something the code states; and the sample set is 472 small files chosen to exercise modules, not production's mix, where most files are an email's parts and their attachments.

### What a task that stores nothing costs now

From the run on this change. The parser pool's container used 1,110 core-seconds for 150,276 task processes, 7.4 ms a task, of which the task process is about 3 and the rest the supervisor's: the lease, the file's download, the task's directory, starting the process, the end. The core and Postgres used 2,389 for 232,927 tasks, 10.3 ms a task, and the bucket 247, 1.1 ms. So a parser task costs the stack about 19 ms of CPU on average, and 3 of them are its own process. The sandbox pool's 11.9 ms a task includes the tools its modules run, so a sandbox task that declines is taken to cost what a parser task does.

Those are averages over every task. A task that stores nothing costs less than the average in its pool, which runs no module work and uploads nothing for it, and in the core, which lands no result, and nothing here measured how much less. So each option's saving below is a range: at least the task process alone, 3.3 ms a parser or sandbox task, and at most the average, 18.8 ms a parser or sandbox task and 11.4 ms a lookup. A run on this change used 4,448 core-seconds.

The wall time is another matter. A run is bounded by how fast the parser pool leases (above), so until that changes, a run is shorter by about the share of the parser pool's tasks that go.

### The options

**1. Leave it.** Nothing more is at risk, and the price is the one above on every root: 199,921 tasks a run that store nothing, 600 to 3,700 core-seconds of the run's 4,448 by the same range.

**2. The module says what it takes, from facts the core holds.** A module gets one more function beside `analyze`, `takes`, given only what the core already has when it decides: the observable's type and value, its directives and tags, the file's name, size and stored mime type, which modules added it, its dependencies' results, and the module's own settings. It returns yes or why not. The core calls it where it calls `eligibility::check` today, and `run_parser` calls the same function again in the task process before `analyze`, so a task queued before the facts changed still declines the same way. This is ace3's `accepts()` and `custom_requirement()`, which are module code the engine runs before it runs the module. The `ace` binary already links every module for its catalog.

- Removes up to 67,993 tasks a run (34.0% of those that store nothing, 29.2% of all tasks): 55,013 parser processes, 8,914 sandbox processes and 4,066 lookups. That is 210 to 1,250 core-seconds a run, 5% to 28%, and 37% of the parser pool's leases.
- Risk: a `takes` that says no where `analyze` would have found something is a missed detection. It can't differ from the module's own check if it is the module's own check, moved: the module's `analyze` no longer has the test, `takes` has it, and both paths go through `takes`. What can differ is the facts. A file's name, the modules that added it, a tag and the root's tree all grow after the first decision, so the core has to ask again when one changes, as it already does when a result adds a directive a module requires. A fact that is read once and never asked about again is the failure to look for.
- Risk: module code runs in the core, on strings an attacker chose (a file's name, a URL). The core already runs its own code on those strings, including the observable modifier's regular expressions. `takes` gets no file bytes. A `takes` that panics must be caught and count as yes.
- Shown equivalent by: the 472-sample comparison coming out the same, with the same count of results by module (34,290); and an audit setting, kept for a while in production, under which the core queues every task as today and the pool reports any task whose `takes` said no and whose `analyze`, run anyway, stored a result. That count has to be zero before the setting goes.

**3. The core compares declared bytes with the file's head.** The store keeps the first kilobyte of each object beside its mime type, and a module's manifest declares the bytes it needs as data: a magic number at an offset, a marker somewhere in the head, an extension. The core compares them; no module code sees the bytes, so nothing of a parser's runs in the core on file content.

- Removes up to about 69,000 more tasks a run (the fixed-byte checks: 46,000 parser processes and 23,000 sandbox ones), 230 to 1,300 core-seconds and another 31% of the parser pool's leases. About 30,000 more, 100 to 570 core-seconds, if libmagic's stored answer can stand in for the modules that ask libmagic themselves, which has to be shown module by module.
- Risk: the declaration must say exactly what the module's check says, and several are not one comparison: a PDF is `%PDF` in the first 1,024 bytes or a name, an Office file an extension or one of two magic numbers. A declaration that is narrower than the check loses a detection, and one that is wider only loses the saving. So each is written wider where in doubt, and the module keeps its own check.
- Cost: a column and a kilobyte a file in the store, and the store reading the head when a file is uploaded, which it already does for libmagic.
- Shown equivalent by: the same audit as option 2, and a test for each module that feeds its declaration and its own check the same files, the sample set's and crafted ones, and asserts the declaration never says no where the check says yes.

**4. One sniffing task for a file.** One contained process a file runs every module's cheap check and tells the core which modules to queue.

- Removes about as many tasks as 2 and 3 together, for one more process a file in each pool (4,066 files in a run), and needs no declaration language, since the checks stay code.
- Risk: it puts every module's decision about a hostile file in one process that reads the file. A parser that is exploited today can forge its own result and no other. A sniffer that is exploited can say that no module takes the file, the YARA scan included, and the file goes unanalysed with nothing failed. That is a wider thing to trust than anything a task process is trusted with now, and it is why this is not the recommendation. Failing open on a crash or a deadline doesn't cover a sniffer that answers.
- It also brings back a process that builds many modules, the cost this step removed, unless the checks are kept free of `init`'s state.

**5. One process for a file's tasks in a pool.** The supervisor leases a file's queued tasks together and one process runs their modules in turn.

- Saves the processes and the downloads, not the queue's rows, the leases or the ends, which are most of what is left.
- Risk: a module that crashes, hangs or exhausts its memory takes the others' tasks on that file with it, and one deadline and one memory limit cover several modules. A module exploited by the file can forge the others' results for that file. PLAN.md 2.17 to 2.19 are written for one task a process.

### Recommendation

Option 2 first, alone, as one step with the audit setting: it removes a third of the tasks that store nothing using only what the core already holds, adds no storage and no new thing to trust, and it is how ace3 already divides the work. Its numbers say whether option 3 is worth its declarations: after option 2 about 99,000 first-byte tasks a run remain, and whether they matter depends on what a task costs then, which the lease loop's change would move first.

Not options 4 or 5: each buys its saving by putting several modules' fate on one hostile file in one process.

Two cheaper things the same numbers show, either of which could go first:

- **Five parsers and three sandbox modules read libmagic's 10.4 MB database in `init`**, 1.5 to 2 ms each, about 37 core-seconds a run here. Two of them then decline without asking it: `phishkit_analyzer` declined all 3,689 of its tasks on a directive, and `cve_2021_30657_analyzer` 4,057 of 4,066 on the file's name, 12 core-seconds for nothing. Mapping the file instead of reading it would cost a task nothing until it asks.
- **`ioc_extraction` compiles its patterns in 12 ms and `ocr` reads its dictionary in 8 ms**, on each of their own tasks now. Neither ran in the comparison. Where they do run, building them on first use inside `analyze` isn't possible for the dictionary, which is a file read before containment, but the patterns could be.

### What is the owner's to decide

1. Whether to build option 2, and whether module code may run in the core for it (`takes`), or the checks must be declared as data only, which covers fewer of them.
2. Whether a kilobyte of each file may be kept in the store for option 3, if it comes to that.
3. How long the audit setting stays on in production before the core stops queueing what `takes` declines.
4. Whether a change to the overlay under a running parser pool now needing a restart is acceptable. It is what this step does, and it is what a network pool always did.

## Not measured

- A production ruleset. With the signatures' ruleset `memory.md` measured 77 ms more a task process, which only YARA tasks pay now; the saving on a real stack should be larger than here by about that much a non-YARA parser task, and it wasn't measured.
- A machine with fewer CPUs, and a pool with more than 16 slots.
- The supervisor's own work for a task, split from the task process, and a lease request's time.
- Memory. A task process that builds one module holds less than one that built 53, and `memory.md`'s figures weren't taken again.
