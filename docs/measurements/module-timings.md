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
- **ace-rs's analyze is slower in a few modules:** `user_defined_tagging` (4.76 s against 0.71 s), `file_hash_analyzer`, `html_data_url_extraction`, `parse_url` and `tls_keylog`. Only the first is worth a look on its own, below.
- **ace-rs's per-task cost dominates modules that are queued on every file and do almost nothing.** `active_mime`, `autoit`, `hidden_mime`, `html_data_url_extraction`, `tls_keylog`, `zip_encryption_analyzer`, `rar_encryption_analyzer` and `msoffice_encryption_analyzer` each run about 4,000 times for about 30 s of slot time and about 13 s of CPU, almost all of it the task's start and end.
- **A module's runs can be higher in ace-rs.** `lure_url_analyzer` (15,136 against 5,774) and `rdap_analyzer` (710 against 449) run more often. Why wasn't looked into.

## What else the numbers include

- **ace3's `custom_requirement` checks aren't timed** (above), so its totals are lower than its real cost wherever a module has one.
- **ace3's CPU per module** is the whole process's CPU across `analyze`, so its monitor and logging threads are included.
- **ace-rs's analyze for `file_type` is missing in one sample** (`ace3/email/splunk_logging.email.rfc822`): 4 runs of about 2.6 ms each, with no analyze or CPU. This happened in every run. A task that ends when it's leased, before any pool runs it, records only the core's time (`ace_core::metrics`). That is the likely reason, and it wasn't confirmed. `file_type`'s analyze and CPU totals are therefore "n/a".
- **ace-rs's lookup tasks have no CPU,** so `nrd_analyzer`, `rdap_analyzer`, `proxy_domain_splunk`, `user_defined_tagging` and `observable_detection` show "n/a".
- **Lookups at one slot change the lookups' own figures.** An earlier set of three runs, with the lookups pool at 16 slots and the scanners pool at 4, gave the parser and sandbox modules' totals within 3% of these. The lookup modules took longer: `user_defined_tagging` 11.8 s of analyze and 81 s of slot, `nrd_analyzer` 2.6 s of analyze. Those runs compared against the committed trees, so they aren't used here.
- **The analysis cache was off** (`tests/e2e/site/overlay.yaml`), so every module ran. There were no cache hits on either side.
- **This is one machine,** with ace3's stack idle beside it and a site's dev stack with two containers restarting in a loop. Across the three runs, the whole set's totals are within 4% of each other, except ace3's CPU of module work (1,213 to 1,328 s, 9%). Some modules vary more: ace3's `msoffice_encryption_analyzer` analyze ranges from 46.1 to 65.2 s.

## Found and left

- **Declarations that would skip most of the per-task cost.** `autoit` declares nothing about which files it takes (`crates/ace-mod-sandbox/src/autoit.rs`), so the core queues it on every file and `is_autoit` runs inside `analyze`. "The file's type is PE, or its name ends `.au3`" can be checked by the core. The other modules queued on every file (`active_mime`, `hidden_mime`, `html_data_url_extraction`, `tls_keylog` and the three encryption analyzers) may be the same, though some of them do real work on the files they take. Together these are about 250 s of slot time over the set, 29% of ace-rs's total.
- **`user_defined_tagging` takes 7 times as long in ace-rs** (4.76 s against 0.71 s over 9,492 runs), with 25 s of slot time. It has no CPU recorded, so it runs in a shared process.
- **ace3's snapshot of the root around `observable_modifier`** costs 1,838 s over the sample set, against 4.4 s for the module. That is a finding about ace3, not ace-rs, and it applies wherever ace3 snapshots the root for a module that runs on every observable.
- **ace3's `custom_requirement` checks** could be timed by the same wrapper, which would make ace3's totals complete. They weren't, so that all three runs stayed alike.
- **The other containers' CPU** (core, Postgres, bucket, lookups, scanners) during these runs, which `compare-speed.md`'s cgroup reading would give.
