# Batch 5's Office container modules against crafted files

PLAN.md 7.5: a contained parser task is one thread with no exec, so each module is bounded for hostile input, and what crafted input costs it is measured against its limits. The modules have the default 300 s, 1 GiB and 300 CPU seconds. ace3 gives them its default `maximum_analysis_time` of 60 s, and runs officeparser3 as a process with its own 90 s timeout. What bounds each:

- `officeparser3` runs a port of officeparser3 in the task. officeparser3 finds a loop in a sector chain by searching a Python list of every sector before it, and builds a decompressed macro a byte at a time by copying the bytes so far, both quadratic; the port uses a set and a growing buffer. A chain that loops in its checks is found when it comes back to a sector, where officeparser3 loops until ace3 kills it at 90 s, and the port ends as that does: `officeparser_failed`, `sandbox` and an empty manifest. Past 256 MiB written to its output directory, which it holds in memory, the port stops the same way, and past 64 Mi FAT entries it raises `MemoryError`, where officeparser3 would be killed or run out of time. It adds at most 500 files.
- `onenote_extraction` reads at most `max_bytes` (100 MiB), as ace3 does, and writes at most 500 files.
- `active_mime` inflates at most 256 MiB, as olevba's ActiveMime does, past which there's no result; ace3 inflates until Python runs out of memory.
- `hidden_mime` searches with the regex crate, linear in the file; Python's feed parser raises `RecursionError` past 971 nested multiparts in ace3, and the port raises it at the same depth, without recursing. It writes at most 500 parts.
- `xml_binary_analyzer`, `office_xml_rel` and `xml_plain_text_analyzer` parse with libxml2 as lxml does, with its limits: 256 levels of nesting, its guard on entity expansion, and no external entities. `xml_binary_analyzer` writes at most 500 parts and `office_xml_rel` adds at most 500 URLs. `xml_plain_text_analyzer` reads at most `maximum_size` (128 KiB), as ace3 does.
- `extracted_ole_analyzer` reads its file for file_type's JavaScript check, which `docs/measurements/javascript-check.md` measures.

The 500s are ace3's `maximum_observable_count` for files and URLs in a root, which ace-rs's core doesn't have.

Measured on 2026-11-09 on the dev container of `build-loop.md` (Rancher Desktop, 10 CPUs), with ace3's and budge's stacks up.

## Command

`tools/samples/make-office-hostile <dir>` writes the files. In the dev container:

    ACE_RS_OFFICE_HOSTILE=<dir> ACE_RS_OFFICE_MODULE=<module> cargo test -p ace-pool --features test-pools \
        --test supervisor measure_office -- --ignored --nocapture

submits each file whose name starts with the module's to the real supervisor, which runs the module, and `file_type` first for `officeparser3` and `hidden_mime`, which wait for it, as `ace-rs-task` under Landlock and seccomp with their limits. 3 runs each, each in a new root under a new name; a `.rels` file is named `document.xml.rels` in its root, the one name `office_xml_rel` reads. The time runs from the root's submission to the end of the module's task on the file, so it includes the upload, the lease, the task process's start, file_type's task where there is one, and the uploads of the module's files. It's a dev build, unoptimized but for the crates `Cargo.toml` raises.

## Results

| File | Size | Module | End | Files | Seconds, 3 runs |
|---|---|---|---|---|---|
| `many_streams.doc`: 40,000 directory entries that each name one 64 KiB chain | 5,227,520 | officeparser3 | done | 499 | 8.50 to 8.56 |
| `long_chain.doc`: one stream of 98,304 sectors, 48 MiB | 50,732,544 | officeparser3 | done | 1 | 0.77 to 1.71 |
| `dif_repeats.doc`: a DIFAT naming one FAT sector 2.5 million times | 10,241,024 | officeparser3 | done, no result | 0 | 1.80 to 1.81 |
| `check_loop.doc`: a stream whose chain comes back on itself | 9,728 | officeparser3 | done, `officeparser_failed` | 0 | 0.26, 0.26, 0.26 |
| `big_macro.doc`: a module of 4 MB of source | 4,648,960 | officeparser3 | done | 5 | 0.41 to 0.63 |
| `copy_tokens.doc`: a dir stream of copy tokens past 64 KiB in one chunk | 7,168 | officeparser3 | done | 3 | 0.31, 0.31, 0.31 |
| `many_10mb.one`: 201,649 objects of 8 bytes | 10,486,772 | onenote_extraction | done | 499 | 3.75 to 4.21 |
| `huge_90mb.one`: one object of 90 MiB | 94,372,908 | onenote_extraction | done | 1 | 0.88 to 0.94 |
| `lengths.one`: 100,000 objects that claim 2^63 bytes | 4,401,024 | onenote_extraction | done, no file | 0 | 0.15 to 0.16 |
| `bomb_1gib.mso`: 1 GiB of zeros in 1 MB of zlib | 1,043,694 | active_mime | done, no result | 0 | 3.00 to 7.02 |
| `parts_10mb.txt`: 327,680 parts of one byte | 10,485,809 | hidden_mime | done | 499 | 3.75 to 3.90 |
| `nested_100000.txt`: multiparts 100,000 deep | 6,966,784 | hidden_mime | done, no result | 0 | 0.36, 0.36, 0.36 |
| `headers_10mb.txt`: 291,271 `Content-Type` lines with no boundary, then one with it | 10,485,814 | hidden_mime | done | 1 | 0.62 to 0.74 |
| `big_80mb.xml`: one part of 60 MiB in base64 | 83,886,390 | xml_binary_analyzer | done | 1 | 0.83 to 2.22 |
| `parts_10mb.xml`: 137,970 parts | 10,485,912 | xml_binary_analyzer | done | 499 | 4.06 to 4.32 |
| `deep_100000.xml`: elements 100,000 deep | 700,192 | xml_binary_analyzer | done, nothing extracted | 0 | 0.15 to 0.16 |
| `laughs.xml`: an entity that expands to 10^10 characters | 857 | xml_binary_analyzer | done, nothing extracted | 0 | 0.16, 0.16, 0.16 |
| `many_10mb.rels`: 124,830 external oleObjects with one target | 10,485,786 | office_xml_rel | done | 0, 1 URL | 0.70 to 0.71 |
| `hosts.rels`: 110,000 targets, each a host of its own | 9,678,956 | office_xml_rel | done | 0, 500 URLs | 0.80 to 1.16 |

File names are the module's name and these. Every task ended `done`, well inside its deadline. What each file does:

- `many_streams.doc` names one chain 40,000 times. officeparser3 writes 40,001 files, 2.6 GB, in 58 s in ace3, and ace3 adds 499 of them; the port reads each chain once and holds the same bytes for every file that names it, and the module writes the first and names the bucket's object again for the rest, so the result has 499 files of one object.
- `long_chain.doc` takes officeparser3 30 s, searching a list of the sectors before each one; the port takes a second, most of it the upload.
- `dif_repeats.doc` would give a FAT of 325 million entries; officeparser3 reads past the file's end and raises `IndexError` in 7.6 s, and the port raises `MemoryError` at 64 Mi entries. Neither writes a manifest, so neither has a result.
- `check_loop.doc`'s chain loops in officeparser3's checks; ace3 kills it at 90 s. The port finds the loop when it comes back to a sector and ends as ace3 does: the file tagged `officeparser_failed` and marked `sandbox`, and a result with no files.
- `big_macro.doc` and `copy_tokens.doc` add the files officeparser3's manifest lists, which the comparison below checks file by file; on the copy tokens both raise after the streams, before any macro.
- `many_10mb.one` stops at its 499th file. `lengths.one`'s first object raises, as construct's read does in ace3, so there is a result with no file.
- `bomb_1gib.mso` passes 256 MiB and leaves no result; ace3's `zlib.decompress` holds the whole GiB.
- `nested_100000.txt` raises `RecursionError` at depth 972, as ace3 does, without recursing. `headers_10mb.txt`'s pattern runs to each line's end and fails, linear in the regex crate.
- `deep_100000.xml` passes libxml2's 256 levels and `laughs.xml` its guard on entity expansion, so each parse raises, as lxml's does, and nothing is extracted.
- `hosts.rels` adds 500 URLs and keeps every target in the result's `urls`, as ace3's details do.

A run's first task on a file can take longer than the next two, from the upload and the bucket; the test stack's bucket, held to 1 GiB, was killed once (exit 137) while `big_80mb.xml`'s runs filled it, so it was restarted before each module's runs, as `html.md`'s were.

## ace3's side

officeparser3 itself, as ace3's module runs it, in ace3's dev container on the same `officeparser3_*` files, one run each, while ace3's trees were being made in the same container:

| File | officeparser3 | Seconds | Manifest |
|---|---|---|---|
| `many_streams.doc` | exit 0 | 58.05 | 40,001 lines |
| `long_chain.doc` | exit 0 | 30.45 | 2 lines |
| `dif_repeats.doc` | `IndexError` | 7.55 | none |
| `check_loop.doc` | killed at 90 s | 90.23 | empty |
| `big_macro.doc` | exit 0 | 0.71 | 7 lines, 5 files not empty |
| `copy_tokens.doc` | `struct.error` | 0.04 | 3 lines |

The port was also run against officeparser3 on 1,500 compound files made by changing random bytes, header fields and lengths of 69 of the samples and fixtures (a script outside the repository, seed 5): for each, whether it raised, exited or was killed, whether it made a manifest, and every file it left by name and sha256. officeparser3 had 20 s each. All 1,500 agree: 1,178 raised, 298 finished and 24 looped, which officeparser3 did until its 20 s and the port found by coming back to a sector; every file and manifest of the 1,476 that ended is the same.
