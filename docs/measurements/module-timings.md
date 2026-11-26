# Module timings in ace-rs and ace3, module by module (PLAN.md 3.6)

Comparing how long a root takes in each system doesn't work, because ace-rs runs a root's modules side by side and ace3 runs them one after another ([`docs/root-analysis.html`](../root-analysis.html)). This compares what each module costs instead, over the whole sample set, on both sides. It also compares what the whole set costs.

There have been two measurements. The first, on 2026-11-25 and 26 at ace-rs `862b13ab` plus 3.6's uncommitted changes, found the problems *What the first measurement found* lists; each was fixed or filed. The figures below are the second, on 2026-11-26 at ace-rs `ec68bca3`, after those fixes, with ace3's `custom_requirement` checks timed as well. [`module-timings.tsv`](module-timings.tsv) has every module's median, minimum and maximum on both sides, from the second.

Both ran on one machine: Docker (Rancher Desktop) with 10 CPUs and 31 GiB. ace3's stack and a site's dev stack were on the same VM and idle. ace-rs ran in release images; ace3 was at `ebad554d`. The two sides never ran at the same time, and each ran three times, taking turns. Every figure is the median of the three runs.

## The commands

ace3's trees at the commit that was timed, so that the comparison judges ace-rs against the same ace3:

```
tools/ace3/trees/make-trees
```

The trees it wrote were copied aside and put in place of the committed trees for each ace-rs run, then taken back. The committed trees are of ace3 at `85c8e9e5`.

ace-rs, with every pool at one slot and one sample at a time:

```
ACE_RS_PARSERS_CONCURRENCY=1 ACE_RS_SANDBOX_CONCURRENCY=1 \
ACE_RS_LOOKUPS_CONCURRENCY=1 ACE_RS_SCANNERS_CONCURRENCY=1 \
ACE_RS_E2E_COMPARE_TIMEOUT=14400 ACE_RS_E2E_SAMPLE_TIMEOUT=1800 \
    tests/e2e/run --no-build --compare --jobs 1
```

ace3, in its dev container, every sample:

```
tools/ace3/trees/make-trees --timings DIR
```

The join, over the three runs of each side:

```
tools/timings/compare --ace-rs R1/report.json --ace-rs R2/report.json --ace-rs R3/report.json \
    --ace3 T1 --ace3 T2 --ace3 T3 --json out.json
```

All three ace-rs runs compared 474 samples against ace3's trees at `ebad554d`, with none failed or absent and no unexplained difference, so every sample counts for every module. The comparisons took 1,326 s, 1,323 s and 1,311 s (the first measurement: 1,390 to 1,396 s). Each ace3 run timed all 474 samples, in 81 minutes.

## What each number is

| Name | ace-rs | ace3 |
|---|---|---|
| analyze | the module's `analyze`, timed in the pool, the check of its declaration included | `analyze` and `custom_requirement`, each timed by a wrapper in `run_module.py`, every call counted, declines included |
| slot / executor | `run_seconds`: the lease, the process's start and containment, fetching the file, `analyze`, writing the result | the executor's `total_analysis_time` (`analyze` plus the snapshots of the root around it, the diff and the cache write) and `custom_requirement` |
| CPU | the task process's user and system time, and its tools', from its rusage. None for a lookup task, whose process is shared | `time.process_time()` across `analyze` and `custom_requirement` (every thread of the process) plus the children's rusage |
| runs | tasks that ran | calls of `analyze` |
| checks | | calls of `custom_requirement`, which the executor makes before `analyze` and before its own clock starts |

ace3's `custom_requirement` time is added into its analyze, executor and CPU figures (`tools/timings/compare`), since ace-rs runs the same checks inside `analyze`.

## The whole sample set

| Over 474 roots | ace-rs | ace3 |
|---|---:|---:|
| Module runs | 75,377 (no spread) | 389,015 (388,938 to 389,272), and 158,219 checks |
| analyze | 214 s (213 to 216) | 945 s (941 to 965), 14.0 s of it checks |
| Slot / executor | 728 s (708 to 733) | 2,884 s (2,856 to 2,887) |
| CPU of module work | 418 s (415 to 420), task processes and their tools | 1,198 s (1,179 to 1,290), across `analyze` and the checks |
| CPU of the whole process | not measured | 4,187 s (4,145 to 4,261), its children included |

Against the first measurement, ace-rs ran 36,284 fewer tasks (111,661 then) for 137 s less slot time (865 s then), and 32 s less CPU (450 s then).

- **analyze: ace-rs uses under a quarter of ace3's time** (0.23). Much of the difference comes from a few modules, listed below.
- **ace3's executor time is mostly not module work.** Of its 2,884 s, 1,861 s is `observable_modifier`, whose `analyze` takes 4.4 s over 37,802 runs. The rest of that module's time is the snapshot of the root ace3 takes before and after each call. Across all modules, `analyze` is a third of the executor's time.
- **ace-rs's slot time is 3.4 times its analyze time.** That is the cost of each task, about 8 ms of slot time and 3.5 ms of CPU per parser task before the module does anything, over the modules still queued on almost every file.
- **The whole-process CPU figures can't be compared.** ace3's 4,187 s includes starting Python and importing ace3 once per sample, 1.38 s of CPU on the lightest sample (`ace-rs/office/vba_flatopc.xml`), or about 650 s over the set. The core, Postgres, the bucket and the lookups pool weren't measured on ace-rs's side. [`compare-speed.md`](compare-speed.md) measured those containers at 1,871 s for an earlier build at 8 slots: 613 s for the core, 1,049 s for Postgres and 209 s for the bucket. ace3's `cli` mode has no database or queue at all.

## Module by module

Totals in seconds over the 474 samples. These are modules where either side's analyze total is at least 1 s, or ace-rs's slot total is at least 10 s: 37 of the 69 modules that ran on both sides. The `.tsv` has all of them, with their ranges, and the 6 modules that ran on one side only.

| Module | Runs ace-rs | Runs ace3 | Checks ace3 | analyze ace-rs | analyze ace3 | Slot ace-rs | Executor ace3 | CPU ace-rs | CPU ace3 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qrcode` | 314 | 312 | 50,364 | 64.95 | 150 | 67.64 | 150 | 65.64 | 382 |
| `archive` | 3,458 | 5,210 | 0 | 0.79 | 149 | 33.88 | 150 | 13.46 | 88.38 |
| `proxy_domain_splunk` | 887 | 1,326 | 0 | 1.01 | 110 | 2.93 | 111 | n/a | 6.65 |
| `officeparser3` | 139 | 5,453 | 0 | 0.84 | 95.88 | 4.73 | 96.81 | 0.61 | 130 |
| `exif` | 380 | 5,438 | 0 | 54.31 | 68.30 | 59.34 | 69.24 | 55.14 | 58.32 |
| `xlmdeobfuscator` | 4,074 | 26,328 | 0 | 32.40 | 51.22 | 69.84 | 55.76 | 46.23 | 51.24 |
| `yara_scanner_v3_4` | 4,074 | 5,453 | 0 | 1.47 | 45.99 | 47.04 | 47.09 | 29.92 | 45.90 |
| `msoffice_encryption_analyzer` | 139 | 5,453 | 0 | 0.96 | 42.93 | 2.23 | 43.87 | 1.44 | 203 |
| `pcodedmp` | 212 | 5,453 | 0 | 0.13 | 38.54 | 1.90 | 39.50 | 0.83 | 33.77 |
| `javascript_deobfuscation` | 170 | 5,402 | 0 | 0.18 | 25.45 | 2.45 | 26.36 | 0.73 | 1.92 |
| `extracted_ole_analyzer` | 758 | 5,453 | 0 | 0.10 | 24.68 | 7.29 | 25.77 | 2.52 | 26.85 |
| `pdf_analyzer` | 146 | 5,174 | 0 | 8.18 | 24.46 | 10.81 | 25.36 | 8.33 | 20.96 |
| `olevba_v1_2` | 259 | 5,371 | 0 | 0.33 | 17.80 | 2.62 | 18.77 | 1.19 | 17.45 |
| `file_type` | 4,052 | 5,072 | 0 | n/a | 16.69 | 41.06 | 17.70 | n/a | 17.43 |
| `java_class_decompiler` | 93 | 5,453 | 0 | 14.09 | 15.74 | 15.16 | 16.64 | 27.91 | 28.75 |
| `pdftotext` | 292 | 5,438 | 0 | 3.92 | 10.26 | 7.03 | 11.18 | 4.56 | 7.84 |
| `url_extraction` | 1,935 | 3,057 | 0 | 2.87 | 8.31 | 22.74 | 8.95 | 14.00 | 8.26 |
| `pdf_encryption_analyzer` | 307 | 5,453 | 0 | 0.12 | 5.47 | 2.64 | 6.42 | 1.15 | 9.57 |
| `user_defined_tagging` | 9,492 | 10,852 | 0 | 4.75 | 0.72 | 25.95 | 2.47 | n/a | 0.72 |
| `rar_encryption_analyzer` | 4,074 | 5,453 | 0 | 2.16 | 4.02 | 35.32 | 4.97 | 15.36 | 18.10 |
| `pdf_link_text` | 292 | 292 | 50,519 | 1.35 | 3.81 | 3.82 | 3.87 | 2.38 | 3.13 |
| `pcap_analyzer` | 11 | 5,453 | 0 | 2.11 | 3.20 | 2.59 | 4.09 | 2.04 | 2.67 |
| `nrd_analyzer` | 942 | 941 | 0 | 0.50 | 2.84 | 2.06 | 3.01 | n/a | 2.83 |
| `cve_2021_30657_analyzer` | 9 | 5,453 | 0 | 0.38 | 2.62 | 0.66 | 3.52 | 0.35 | 1.65 |
| `rdap_analyzer` | 710 | 449 | 5,528 | 0.22 | 2.29 | 1.38 | 2.38 | n/a | 2.22 |
| `rtfole` | 38 | 5,453 | 0 | 0.06 | 1.99 | 0.55 | 2.91 | 0.14 | 1.99 |
| `de4dot` | 4 | 5,450 | 0 | 1.34 | 1.76 | 1.40 | 2.67 | 1.35 | 1.59 |
| `zip_encryption_analyzer` | 131 | 5,453 | 0 | 0.01 | 1.70 | 1.14 | 2.64 | 0.45 | 7.19 |
| `autoit` | 21 | 4 | 51,808 | 0.07 | 1.39 | 0.28 | 1.39 | 0.16 | 1.38 |
| `ilspy` | 7 | 5,446 | 0 | 0.95 | 1.36 | 1.10 | 2.26 | 0.91 | 1.16 |
| `html_data_url_extraction` | 4,048 | 5,445 | 0 | 1.31 | 0.26 | 30.98 | 1.15 | 14.67 | 0.26 |
| `file_hash_analyzer` | 1,219 | 5,070 | 0 | 0.17 | 1.12 | 10.43 | 2.05 | 4.34 | 1.12 |
| `hidden_mime` | 3,837 | 5,453 | 0 | 0.76 | 0.84 | 31.64 | 1.73 | 13.87 | 0.83 |
| `observable_detection` | 9,492 | 10,852 | 0 | 0.12 | 0.66 | 23.60 | 7.06 | n/a | 0.66 |
| `tls_keylog` | 4,074 | 5,453 | 0 | 0.57 | 0.20 | 29.77 | 1.09 | 13.54 | 0.19 |
| `lure_url_analyzer` | 4,074 | 5,774 | 0 | 0.17 | 0.40 | 49.99 | 1.34 | 15.58 | 0.38 |
| `active_mime` | 4,054 | 5,453 | 0 | 0.10 | 0.18 | 31.82 | 1.08 | 14.31 | 0.18 |

How to read it:

- **Where both sides spend their time in the same external tool, the two agree.** `exif` (exiftool: 54 s against 68 s) and `java_class_decompiler` (CFR: 14 s against 16 s, 28 s of CPU on each side) both do. That is the check that the two sides measure the same thing.
- **Where ace-rs replaced Python, it is far cheaper.** `archive`, `officeparser3`, `msoffice_encryption_analyzer`, `pcodedmp`, `olevba_v1_2`, `extracted_ole_analyzer` and `yara_scanner_v3_4` each take under 1.5 s in ace-rs against 17 to 149 s in ace3.
- **ace3's checks matter for three modules.** `qrcode`'s took 11.8 s over 50,364 calls, `autoit`'s 1.35 s over 51,808 and `pdf_link_text`'s 0.79 s over 50,519, where each module's `analyze` ran a few hundred times or less. In the first measurement these weren't counted.
- **`proxy_domain_splunk` measures the fakes, not the module.** ace3 asks `fake_splunk.py` and waits on its job's polling. ace-rs is answered by the e2e responder's recording.
- **`user_defined_tagging` and `email_conversation_frequency_analyzer` don't compare,** since their ace3 figures have no database in them. `make-trees` runs ace3 without one, so `run_module.py` answers `user_defined_tagging`'s SELECT from a list in memory (`fake_observable_tags`), and `--brocess` gives the frequency module its smtplog rows from a JSON file. In ace-rs each run is a read through the core's lease API, which queries Postgres (0.50 ms a run). With ace3's own queries timed below (*ace3's database queries*), `user_defined_tagging` is about 0.31 ms a run in ace3 against ace-rs's 0.50 ms, and the frequency module about 0.30 to 0.52 ms against 0.54 ms.
- **ace-rs's per-task cost still dominates the modules queued on almost every file.** `active_mime`, `hidden_mime`, `html_data_url_extraction`, `tls_keylog` and `rar_encryption_analyzer` each run about 4,000 times for about 30 s of slot time and 14 s of CPU, almost all of it the task's start and end; issues #2 to #6 track what each would need. `lure_url_analyzer`, which runs last and reads its root's tree, holds a slot for 12 ms a run (50 s over 4,074) where its `analyze` takes 0.04 ms; where that goes isn't known.
- **`rdap_analyzer` runs more often in ace-rs** (710 against 449) because ace3's check drops IPs that aren't globally routable (5,528 checks), where ace-rs declines them in `analyze`.

## What else the numbers include

- **ace3's CPU per module** is the whole process's CPU across `analyze` and the checks, so its monitor and logging threads are included.
- **ace-rs's analyze for `file_type` is missing in one sample** (`ace3/email/splunk_logging.email.rfc822`): 4 runs of about 2.6 ms each, with no analyze or CPU, in every run of both measurements. A task that ends when it's leased, before any pool runs it, records only the core's time (`ace_core::metrics`). That is the likely reason, and it wasn't confirmed. `file_type`'s analyze and CPU totals are therefore "n/a".
- **ace-rs's lookup tasks have no CPU,** so `nrd_analyzer`, `rdap_analyzer`, `proxy_domain_splunk`, `user_defined_tagging` and `observable_detection` show "n/a".
- **The analysis cache was off** (`tests/e2e/site/overlay.yaml`), so every module ran. There were no cache hits on either side.
- **This is one machine,** with ace3's stack and a site's dev stack idle beside it. Across the three runs, the whole set's totals are within 4% of each other, except ace3's CPU of module work (1,179 to 1,290 s, 9%).

## What the first measurement found

Each of these was found by the first measurement and fixed before the second, or filed:

- **Modules queued on every file.** `autoit`, `msoffice_encryption_analyzer` and `zip_encryption_analyzer` declared nothing about which files they take, so each ran about 4,070 times for about 30 s of slot time. They now declare a PE file or an `.au3`, an OLE file, and a zip, from the file's type: 21, 139 and 131 runs. The other five are issues #2 to #6.
- **The core's waits counted as runs.** When a `RUNS_LAST` task was leased before the rest of its root was done, the core sent it back as if its module had delayed: a run, slot time, and the module's own delay record taken over. That was most of `lure_url_analyzer`'s 15,136 runs and 72 s of slot time, and `email_thread_analyzer`'s 365 runs (ace3: 68). Since migration 0089 the wait counts nothing: 4,074 and 68. `xlmdeobfuscator` (15,287 runs) and `extracted_ole_analyzer` (2,476) dropped with it, to 4,074 and 758.
- **Two costs a fresh task process paid.** A parser task is a process of its own, and paid on every task what ace3 pays once per process:
  - `parse_url` built the public suffix list's tries on its first lookup: 2.04 ms in a fresh process (median of 15, 1.92 to 2.45), nearly all of its 2.3 ms a run. The tries are now built when `ace-pycompat` is compiled: 0.0043 ms. `parse_url`'s analyze went from 1.14 s to 0.03 s.
  - `file_hash_analyzer`'s declaration has 32 globs, and `ace_pycompat::fnmatch` compiled a regex for each on every check, where Python caches each pattern: 1.10 ms a check in a fresh process (median of 15, 0.86 to 1.19), in the parser task and in the core for every file it queued. `fnmatch` now matches without a regex: 0.0097 ms. `file_hash_analyzer`'s analyze went from 2.29 s to 0.17 s.
- **ace3's checks weren't timed,** so ace3's figures were low wherever a module has one. `make-trees --timings` now times `custom_requirement` (`requirement_runs`, `requirement_seconds`, `requirement_cpu_seconds`), and the join counts it.

## ace3's database queries

`make-trees` answers `user_defined_tagging`'s and the conversation frequency module's queries from memory, so their ace3 figures leave the database out. These are ace3's own queries, timed in its dev container against its dev databases, read only, through ace3's `get_db_connection` as the modules call it (a connection pool, its first connection made before the timing):

```
docker exec -i -e PYTHONPATH=/opt/ace -e SAQ_SKIP_LOCAL_SAQ_YAML=1 -w /opt/ace ace-dev-1 \
    /venv/bin/python3 - 2000 3 < tools/ace3/timings/query-bench.py
```

Three runs of 2,000 calls each, on 2026-11-26. Half the tag lookups are for observables the table holds and half for ones it doesn't; the brocess sums are for addresses it doesn't hold.

| Query, per call | Median of the runs' medians | Runs' medians | p10 to p90, over all runs |
|---|---:|---|---|
| `user_defined_tagging`'s SELECT | 0.244 ms | 0.239, 0.244, 0.250 | 0.209 to 0.284 ms |
| brocess sum by sender | 0.229 ms | 0.229, 0.236, 0.218 | 0.206 to 0.270 ms |
| brocess sum by conversation | 0.221 ms | 0.218, 0.221, 0.222 | 0.204 to 0.248 ms |

With these, `user_defined_tagging` is about 0.31 ms a run in ace3 (0.066 ms of module and fake, plus 0.244 ms of query) against ace-rs's 0.50 ms: about 3.3 s over ace3's 10,852 runs against ace-rs's 4.75 s. The frequency module sends ace3 one query a run, and a second only for a sender brocess has seen before, so it comes to between about 0.30 and 0.52 ms a run in ace3, against ace-rs's 0.54 ms.

What else these include, and leave out:
- **ace3's dev databases are nearly empty:** 677 observables, 19 tags, no tag mappings, and an empty smtplog. A query here is mostly its round trip and its planning. How it grows with production's tables isn't measured.
- **The database is on the same Docker VM,** as ace-rs's Postgres was. A production database across a network adds its own round trip to every call.
- **Nothing else was running in ace3's container,** where ace-rs's 0.50 ms a read is from a comparison run, with the other pools' tasks beside it.

## Found and left

- **`lure_url_analyzer`'s 12 ms a run** of slot time, against 0.04 ms of `analyze`: 50 s over the set, the largest slot time of any module ace-rs queues on almost every file. It runs last and reads its root's tree from the core.
- **The modules still queued on almost every file,** issues #2 to #6: about 160 s of slot time over the set between them.
- **ace3's snapshot of the root around `observable_modifier`** costs 1,861 s over the sample set, against 4.4 s for the module. That is a finding about ace3, not ace-rs, and it applies wherever ace3 snapshots the root for a module that runs on every observable.
- **The other containers' CPU** (core, Postgres, bucket, lookups, scanners) during these runs, which `compare-speed.md`'s cgroup reading would give.
