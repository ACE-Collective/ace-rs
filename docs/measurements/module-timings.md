# Module timings in ace-rs and ace3, module by module (PLAN.md 3.6)

Comparing how long a root takes in each system doesn't work, because ace-rs runs a root's modules side by side and ace3 runs them one after another ([`docs/root-analysis.html`](../root-analysis.html)). This compares what each module costs instead, over the whole sample set, on both sides. It also compares what the whole set costs.

Measured on 2026-11-25 and 26 on one machine: Docker (Rancher Desktop) with 10 CPUs and 31 GiB. ace3's stack and a site's dev stack were running on the same VM, idle except for two of the site's containers restarting in a loop. ace-rs was at `862b13ab` plus 3.6's uncommitted changes, in release images. ace3 was at `ebad554d`. The two sides never ran at the same time, and each ran three times. Every figure is the median of the three runs. [`module-timings.tsv`](module-timings.tsv) has every module's median, minimum and maximum on both sides.

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

All three ace-rs runs compared 474 samples against ace3's trees at `ebad554d`, with none failed or absent and no unexplained difference, so every sample counts for every module. The comparisons took 1,396 s, 1,396 s and 1,390 s. Each ace3 run timed all 474 samples, in 81, 80 and 80 minutes.

## What each number is

| Name | ace-rs | ace3 |
|---|---|---|
| analyze | the module's `analyze`, timed in the pool, its checks of what it takes included | `analyze`, timed by a wrapper in `run_module.py`, every call counted, declines included |
| slot / executor | `run_seconds`: the lease, the process's start and containment, fetching the file, `analyze`, writing the result | the executor's `total_analysis_time`: `analyze` plus the snapshots of the root around it, the diff and the cache write |
| CPU | the task process's user and system time, and its tools', from its rusage. None for a lookup task, whose process is shared | `time.process_time()` across `analyze` (every thread of the process) plus the children's rusage |
| runs | tasks that ran | calls of `analyze` |

ace3's executor first checks a module's `custom_requirement` (`saq/engine/executor.py:1408`) and calls `analyze` only if the check passes. The check is outside both ace3 timers. For `autoit` it reads each PE file looking for the AutoIt marker, and ace3 records 4 runs. ace-rs runs the same check inside `analyze`, so it counts. Wherever a module has such a check, ace3's figures are too low.

## The whole sample set

| Over 474 roots | ace-rs | ace3 |
|---|---:|---:|
| Module runs | 111,661 (111,632 to 111,681) | 388,627 (388,344 to 388,897) |
| analyze | 218 s (217 to 218) | 940 s (935 to 946) |
| Slot / executor | 865 s (847 to 874) | 2,832 s (2,832 to 2,840) |
| CPU of module work | 450 s (449 to 451), task processes and their tools | 1,274 s (1,213 to 1,328), across `analyze` |
| CPU of the whole process | not measured | 4,207 s (4,179 to 4,252), its children included |

- **analyze: ace-rs uses about a quarter of ace3's time** (0.23). Much of the difference comes from a few modules, listed below.
- **ace3's executor time is mostly not module work.** Of its 2,832 s, 1,838 s is `observable_modifier`, whose `analyze` takes 4.4 s over 37,802 runs. The rest of that module's time is the snapshot of the root ace3 takes before and after each call. Across all modules, `analyze` is a third of the executor's time.
- **ace-rs's slot time is 4 times its analyze time.** That is the cost of each task: about 7 ms of slot time and 3 ms of CPU per parser task, before the module does anything.
- **The whole-process CPU figures can't be compared.** ace3's 4,207 s includes starting Python and importing ace3 once per sample, 1.38 s of CPU on the lightest sample (`ace-rs/office/vba_flatopc.xml`), or about 650 s over the set. The core, Postgres, the bucket and the lookups pool weren't measured on ace-rs's side. [`compare-speed.md`](compare-speed.md) measured those containers at 1,871 s for an earlier build at 8 slots: 613 s for the core, 1,049 s for Postgres and 209 s for the bucket. ace3's `cli` mode has no database or queue at all.

## Module by module

Totals in seconds over the 474 samples. These are modules where either side's analyze total is at least 1 s, or ace-rs's slot total is at least 20 s: 38 of the 69 modules that ran on both sides. The `.tsv` has all of them, with their ranges, and the 6 modules that ran on one side only.

| Module | Runs ace-rs | Runs ace3 | analyze ace-rs | analyze ace3 | Slot ace-rs | Executor ace3 | CPU ace-rs | CPU ace3 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `archive` | 3,458 | 5,210 | 0.75 | 149 | 33.13 | 150 | 12.46 | 86.54 |
| `qrcode` | 314 | 312 | 64.98 | 137 | 67.52 | 137 | 65.56 | 366 |
| `proxy_domain_splunk` | 887 | 1,326 | 1.05 | 110 | 2.97 | 110 | n/a | 6.71 |
| `officeparser3` | 139 | 5,453 | 0.70 | 95.80 | 4.27 | 96.71 | 0.59 | 130 |
| `exif` | 380 | 5,438 | 53.38 | 66.55 | 58.43 | 67.47 | 54.16 | 57.19 |
| `msoffice_encryption_analyzer` | 4,074 | 5,453 | 1.19 | 55.69 | 33.20 | 56.61 | 13.83 | 302 |
| `xlmdeobfuscator` | 15,287 | 25,929 | 32.29 | 50.94 | 93.64 | 55.24 | 45.48 | 50.97 |
| `yara_scanner_v3_4` | 4,074 | 5,453 | 1.44 | 45.21 | 46.58 | 46.30 | 28.96 | 45.14 |
| `pcodedmp` | 212 | 5,453 | 0.12 | 38.72 | 1.85 | 39.67 | 0.79 | 33.47 |
| `javascript_deobfuscation` | 170 | 5,402 | 0.17 | 25.01 | 2.32 | 25.90 | 0.70 | 1.92 |
| `pdf_analyzer` | 146 | 5,174 | 8.14 | 24.43 | 10.58 | 25.31 | 8.32 | 20.74 |
| `extracted_ole_analyzer` | 2,476 | 5,453 | 0.10 | 23.97 | 10.40 | 25.03 | 2.38 | 26.09 |
| `olevba_v1_2` | 259 | 5,371 | 0.32 | 17.53 | 2.50 | 18.48 | 1.12 | 17.23 |
| `file_type` | 4,052 | 5,072 | n/a | 16.30 | 41.00 | 17.28 | n/a | 17.02 |
| `java_class_decompiler` | 93 | 5,453 | 14.05 | 15.84 | 15.06 | 16.73 | 28.16 | 28.76 |
| `pdftotext` | 292 | 5,438 | 3.84 | 10.20 | 6.78 | 11.10 | 4.44 | 7.64 |
| `url_extraction` | 1,935 | 3,057 | 4.92 | 8.14 | 24.43 | 8.77 | 15.37 | 8.10 |
| `pdf_encryption_analyzer` | 307 | 5,453 | 0.12 | 5.55 | 2.43 | 6.49 | 1.04 | 8.65 |
| `user_defined_tagging` | 9,492 | 10,852 | 4.76 | 0.71 | 25.13 | 2.43 | n/a | 0.71 |
| `rar_encryption_analyzer` | 4,074 | 5,453 | 2.16 | 3.90 | 33.67 | 4.82 | 14.49 | 17.98 |
| `pcap_analyzer` | 11 | 5,453 | 2.02 | 3.17 | 2.49 | 4.04 | 1.95 | 2.52 |
| `pdf_link_text` | 292 | 292 | 1.33 | 3.05 | 3.57 | 3.11 | 2.27 | 2.26 |
| `nrd_analyzer` | 942 | 941 | 0.48 | 2.83 | 1.93 | 3.00 | n/a | 2.83 |
| `cve_2021_30657_analyzer` | 9 | 5,453 | 0.37 | 2.61 | 0.61 | 3.49 | 0.34 | 1.61 |
| `file_hash_analyzer` | 1,219 | 5,070 | 2.29 | 1.11 | 12.13 | 2.02 | 6.29 | 1.10 |
| `rdap_analyzer` | 710 | 449 | 0.22 | 2.16 | 1.29 | 2.24 | n/a | 2.10 |
| `zip_encryption_analyzer` | 4,074 | 5,453 | 0.17 | 2.04 | 32.90 | 2.96 | 12.96 | 11.02 |
| `rtfole` | 38 | 5,453 | 0.05 | 1.97 | 0.53 | 2.86 | 0.14 | 1.97 |
| `de4dot` | 4 | 5,450 | 1.35 | 1.79 | 1.41 | 2.68 | 1.35 | 1.61 |
| `ilspy` | 7 | 5,446 | 0.94 | 1.46 | 1.09 | 2.34 | 0.91 | 1.16 |
| `html_data_url_extraction` | 4,048 | 5,445 | 1.30 | 0.25 | 29.80 | 1.13 | 13.92 | 0.25 |
| `parse_url` | 500 | 499 | 1.14 | 0.36 | 4.01 | 0.44 | 2.82 | 0.33 |
| `hidden_mime` | 3,837 | 5,453 | 0.77 | 0.83 | 30.55 | 1.70 | 13.13 | 0.82 |
| `observable_detection` | 9,492 | 10,852 | 0.12 | 0.66 | 22.76 | 6.95 | n/a | 0.66 |
| `tls_keylog` | 4,074 | 5,453 | 0.56 | 0.19 | 28.29 | 1.07 | 12.74 | 0.19 |
| `lure_url_analyzer` | 15,136 | 5,774 | 0.17 | 0.40 | 72.25 | 1.32 | 14.83 | 0.38 |
| `active_mime` | 4,054 | 5,453 | 0.08 | 0.18 | 30.44 | 1.06 | 13.12 | 0.18 |
| `autoit` | 4,072 | 4 | 0.18 | 0.04 | 34.02 | 0.04 | 14.34 | 0.05 |

How to read it:

- **Where both sides spend their time in the same external tool, the two agree.** `exif` (exiftool: 53 s against 67 s) and `java_class_decompiler` (CFR: 14 s against 16 s, 28 s of CPU on each side) both do. That is the check that the two sides measure the same thing.
- **Where ace-rs replaced Python, it is far cheaper.** `archive`, `officeparser3`, `msoffice_encryption_analyzer`, `pcodedmp`, `olevba_v1_2`, `extracted_ole_analyzer` and `yara_scanner_v3_4` each take under 1.5 s in ace-rs against 17 to 149 s in ace3.
- **`proxy_domain_splunk` measures the fakes, not the module.** ace3 asks `fake_splunk.py` and waits on its job's polling. ace-rs is answered by the e2e responder's recording.
- **ace-rs's analyze is higher in a few modules:** `user_defined_tagging` (4.76 s against 0.71 s), `file_hash_analyzer`, `html_data_url_extraction`, `parse_url`, `tls_keylog` and `email_conversation_frequency_analyzer`.
  - `user_defined_tagging` and `email_conversation_frequency_analyzer` don't compare: their ace3 figures have no database in them. `make-trees` runs ace3 without one, so `run_module.py` answers `user_defined_tagging`'s SELECT from a list in memory (`fake_observable_tags`), and `--brocess` gives the frequency module its smtplog rows from a JSON file. In ace-rs each run is a read through the core's lease API, which queries Postgres (0.50 ms a run, against ace3's 0.066 ms for a scan of a list). In production, ace3 sends the same SELECT to its database for every observable, which these figures leave out.
  - What those queries cost ace3 was measured on its own, below (*ace3's database queries*). With it, `user_defined_tagging` is about 0.31 ms a run in ace3 (0.066 ms of module and fake, plus 0.244 ms of query) against ace-rs's 0.50 ms: 1.6 times, not 7.6. Its total would be about 3.3 s over ace3's 10,852 runs, against ace-rs's 4.76 s. The frequency module sends ace3 one query a run, and a second only for a sender brocess has seen before (0.229 and 0.221 ms), so it comes to between about 0.30 and 0.52 ms a run in ace3, against ace-rs's 0.54 ms.
- **ace-rs's per-task cost dominates modules that are queued on every file and do almost nothing.** `active_mime`, `autoit`, `hidden_mime`, `html_data_url_extraction`, `tls_keylog`, `zip_encryption_analyzer`, `rar_encryption_analyzer` and `msoffice_encryption_analyzer` each run about 4,000 times for about 30 s of slot time and about 13 s of CPU, almost all of it the task's start and end.
- **A module's runs can be higher in ace-rs, for two reasons found since.**
  - The core counted each wait of a `RUNS_LAST` module for the rest of its root as a run of the module, with the lease's own time as slot time, though no pool saw the task. That is most of `lure_url_analyzer`'s runs (15,136 against 5,774) and slot time, and `email_thread_analyzer`'s. On `ace-rs/pcap/many_hosts.pcap`, `lure_url_analyzer` had 206 runs, 51 without the waits, as in ace3. Fixed since (migration 0089): the wait counts nothing.
  - `rdap_analyzer` (710 against 449) runs on IPs that aren't globally routable, and declines them in `analyze`. ace3 drops them in its `custom_requirement`, before its count.

## What else the numbers include

- **ace3's `custom_requirement` checks aren't timed** (above), so its totals are lower than its real cost wherever a module has one.
- **ace3's CPU per module** is the whole process's CPU across `analyze`, so its monitor and logging threads are included.
- **ace-rs's analyze for `file_type` is missing in one sample** (`ace3/email/splunk_logging.email.rfc822`): 4 runs of about 2.6 ms each, with no analyze or CPU. This happened in every run. A task that ends when it's leased, before any pool runs it, records only the core's time (`ace_core::metrics`). That is the likely reason, and it wasn't confirmed. `file_type`'s analyze and CPU totals are therefore "n/a".
- **ace-rs's lookup tasks have no CPU,** so `nrd_analyzer`, `rdap_analyzer`, `proxy_domain_splunk`, `user_defined_tagging` and `observable_detection` show "n/a".
- **Lookups at one slot change the lookups' own figures.** An earlier set of three runs, with the lookups pool at 16 slots and the scanners pool at 4, gave the parser and sandbox modules' totals within 3% of these. The lookup modules took longer: `user_defined_tagging` 11.8 s of analyze and 81 s of slot, `nrd_analyzer` 2.6 s of analyze. Those runs compared against the committed trees, so they aren't used here.
- **The analysis cache was off** (`tests/e2e/site/overlay.yaml`), so every module ran. There were no cache hits on either side.
- **This is one machine,** with ace3's stack idle beside it and a site's dev stack with two containers restarting in a loop. Across the three runs, the whole set's totals are within 4% of each other, except ace3's CPU of module work (1,213 to 1,328 s, 9%). Some modules vary more: ace3's `msoffice_encryption_analyzer` analyze ranges from 46.1 to 65.2 s.

## Two costs a parser task pays because it is a fresh process

`file_hash_analyzer` (1.9 ms a run in ace-rs against 0.22 ms in ace3) and `parse_url` (2.3 against 0.72 ms, on the same 500 runs) aren't slower in their own work. Most of their time goes on building something ace3 builds once per process, which a parser task, a process of its own, builds again every time. Both were timed with throwaway release builds of `ace-pycompat` in the dev container, on 2026-11-26; the examples weren't kept.

- **`parse_url`: the public suffix list.** `is_netloc_valid_tld` reads `ace_pycompat::tld`'s trie, built from the embedded `effective_tld_names.dat` the first time a process asks (`LazyLock`). The first lookup in a fresh process took 2.04 ms (median of 15 processes, 1.92 to 2.45), the next one 0.0007 ms. That is nearly all of `parse_url`'s 2.3 ms a run. Every other parser task that asks for a TLD pays it once too (`url_extraction` among them). Fixed since: the tries are built when the crate is compiled (`ace-pycompat`'s `build.rs`), and the first lookup in a fresh process takes 0.0043 ms (median of 15, 0.0035 to 0.0078).
- **`file_hash_analyzer`: its declaration's globs.** The pool checks a module's declaration again inside the time it counts as `analyze` (`ace_sdk::run_parser`'s `declined`). `file_hash_analyzer`'s declaration is 28 path globs and 4 mime globs (ace3's `ignore_pattern_*` and `ignore_mime_type_*`), and `ace_pycompat::fnmatch` compiled a regex for each on every call, where Python's `fnmatch` caches each compiled pattern. One check of 30 of them in a fresh process took 0.89 ms (median of 15, 0.78 to 1.03), and of all 32, 1.10 ms (median of 15, 0.86 to 1.19); in a warm loop, 0.66 ms a check of the 30 compiling each time (three runs: 0.657, 0.640, 0.677) against 0.0017 ms with the patterns compiled once. That is about half of `file_hash_analyzer`'s 1.9 ms a run; the rest wasn't found. The core checks the same declaration for every file it queues, in a process that does keep running, so it compiled the same patterns again for each file. Fixed since: `fnmatch` matches without a regex, and a check of the 32 takes 0.0097 ms in a fresh process (median of 15, 0.0077 to 0.0115) and 0.0063 ms warm.

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

What else these include, and leave out:
- **ace3's dev databases are nearly empty:** 677 observables, 19 tags, no tag mappings, and an empty smtplog. A query here is mostly its round trip and its planning. How it grows with production's tables isn't measured.
- **The database is on the same Docker VM,** as ace-rs's Postgres was. A production database across a network adds its own round trip to every call.
- **Nothing else was running in ace3's container,** where ace-rs's 0.50 ms a read is from a comparison run, with the other pools' tasks beside it.

## Found and left

- **Declarations that would skip most of the per-task cost.** `autoit` declares nothing about which files it takes (`crates/ace-mod-sandbox/src/autoit.rs`), so the core queues it on every file and `is_autoit` runs inside `analyze`. "The file's type is PE, or its name ends `.au3`" can be checked by the core. The other modules queued on every file (`active_mime`, `hidden_mime`, `html_data_url_extraction`, `tls_keylog` and the three encryption analyzers) may be the same, though some of them do real work on the files they take. Together these are about 250 s of slot time over the set, 29% of ace-rs's total.
- **ace3's snapshot of the root around `observable_modifier`** costs 1,838 s over the sample set, against 4.4 s for the module. That is a finding about ace3, not ace-rs, and it applies wherever ace3 snapshots the root for a module that runs on every observable.
- **ace3's `custom_requirement` checks** are timed by `make-trees --timings` since these runs (`requirement_runs`, `requirement_seconds`, `requirement_cpu_seconds`), and `tools/timings/compare` adds them to ace3's figures. The figures above are from before, without them. On `ace3/executables/hello_autoit.exe` alone, three modules have a check: `autoit`'s ran 67 times in 2.7 ms, and `qrcode`'s and `pdf_link_text`'s 88 times each, where neither module's `analyze` ran.
- **The other containers' CPU** (core, Postgres, bucket, lookups, scanners) during these runs, which `compare-speed.md`'s cgroup reading would give.
