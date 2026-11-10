# Batch 6's RTF and script modules: the decoder against its Perl, and crafted files

PLAN.md 7.5 batch 6. `microsoft_script_encoding_analysis` decodes with a port of the Perl decoder ace3 runs, `bin/jscript.decode.pl`, so the port is checked against the Perl byte for byte. A contained parser task is one thread with no exec, so each module is also bounded for hostile input, and what crafted input costs it is measured against its limits.

Each module has ace3's default `maximum_analysis_time`, 60 s, with 1 GiB and 60 CPU seconds, and each reads its file once, in time and memory linear in its size:

- `microsoft_script_encoding_analysis` holds the file and what it decodes, at most as large. ace3 runs the Perl as a process, which reads the file into one string and splits it into one Perl string per byte.
- `vbscript_analyzer` reads the file and counts runs of hex digits, keeping one length per run.
- `nowhitespace_analyzer` streams the file through 1 MiB reads into the bucket, as ace3 reads 1 MiB chunks.
- `extracted_rtf_analyzer` reads nothing but file_type's result and its file's path, so it isn't measured.

Measured on 2026-11-09 on the dev container of `build-loop.md` (Rancher Desktop, 10 CPUs, 24 GB), with ace3's and budge's stacks up and ace3's trees being made in its container.

## The decoder against the Perl

`tools/samples/compare-mse-decoder COUNT SEED` writes the inputs: the 21 fixtures of `tools/ace3/dumps/fixtures/scripts/mse`, the 3 samples under `samples/ace4/scripts`, 27 edge cases written by hand (each step's markers and numbers present, missing, empty or `0`, every escape, an escape at the end, bytes past 0x7f, NUL, two blocks) and COUNT more made from them by a seeded generator, which cuts them short, changes, inserts and deletes bytes, inserts markers, numbers, escapes, newlines and high bytes, and writes random bytes after a start marker. The Perl runs on each in ace3's dev container and the port in ace4's, through `cargo test -p ace-mod-scripts --test reference decoder_outputs -- --ignored`, and the script compares, for each input, the sha256 of what each printed and the message each died with.

| Seed | Inputs | Died | Printed nothing | Decoded | Differ |
|---|---|---|---|---|---|
| 1 | 10,051 | 6,866 | 3 | 3,182 | 0 |
| 2 | 10,051 | 6,887 | 3 | 3,161 | 0 |
| 3 | 10,051 | 6,907 | 3 | 3,141 | 0 |
| 4 | 10,051 | 6,952 | 3 | 3,096 | 0 |
| 5 | 10,051 | 6,930 | 5 | 3,116 | 0 |

The first run, before the port knew it, found 38 differences, all one Perl behaviour: each of the first three steps is `(m/.../ and $_ = $')`, whose value is the string assigned, so when what's left is empty or `0`, which Perl takes as false, the step dies as if its match had failed. `#@~^` alone dies `Start marker not found`, and `#@~^AAAAAA==^#~@` dies `No leading checksum`. `mse::decode` now does the same.

Of the crafted files below, `big_90mb.vbe`'s decoded script is the Perl's to the byte, by sha256. For `high_90mb.vbe` only the length was checked, 94,371,840 bytes on both sides, since the one Perl run that finished wrote its output to a file that was then removed; bytes past 0x7f are among what the comparison above covers.

## Crafted files

`tools/samples/make-scripts-hostile <dir>` writes the files. In the dev container:

    ACE4_SCRIPTS_HOSTILE=<dir> ACE4_SCRIPTS_MODULE=<module> cargo test -p ace-pool --features test-pools \
        --test supervisor measure_scripts -- --ignored --nocapture

submits each file whose name starts with the module's to the real supervisor, which runs the module as `ace4-task` under Landlock and seccomp with its limits. 3 runs each, each in a new root under a new name. The time runs from the root's submission to the end of the module's task on the file, so it includes the upload, the lease, the task process's start and the upload of the file the module writes. It's a dev build, unoptimized.

| File | Size | Module | End | Files | Seconds, 3 runs |
|---|---|---|---|---|---|
| `big_90mb.vbe`: an encoded script of 90 MiB | 98,786,902 | microsoft_script_encoding_analysis | done | 1 | 1.81 to 2.73 |
| `escapes_90mb.vbe`: 45 Mi escapes | 94,371,856 | microsoft_script_encoding_analysis | done | 1 | 1.09 to 1.76 |
| `high_90mb.vbe`: 90 MiB of 0xff | 94,371,856 | microsoft_script_encoding_analysis | done | 1 | 1.29 to 2.11 |
| `no_end_90mb.vbe`: no end marker | 94,371,852 | microsoft_script_encoding_analysis | done, no file | 0 | 0.15 to 0.21 |
| `markers_90mb.vbe`: start markers only | 94,371,840 | microsoft_script_encoding_analysis | done, no file | 0 | 0.21, 0.21, 0.21 |
| `hex_90mb.vbs`: one run of 90 Mi hex digits | 94,371,840 | vbscript_analyzer | done | 0 | 1.13 to 1.14 |
| `runs_90mb.vbs`: 15 million runs of 5 | 94,371,840 | vbscript_analyzer | done | 0 | 1.68 to 1.73 |
| `lengths.vbs`: one run of each length from 5 to 12,999 | 84,506,484 | vbscript_analyzer | done | 0 | 0.94 to 0.99 |
| `lines_90mb.vbs`: 31 million lines, half of them comments | 78,643,200 | vbscript_analyzer | done | 0 | 1.56 to 1.60 |
| `spaces_90mb.rtf`: an RTF of 90 MiB of spaces | 94,371,847 | nowhitespace_analyzer | done | 1 | 1.55 to 1.60 |
| `mixed_90mb.rtf`: 80 MB, two thirds whitespace | 80,890,153 | nowhitespace_analyzer | done | 1 | 1.72 to 2.16 |

File names are the module's name and these. Every task ended `done`, well inside its deadline.

## ace3's side

The Perl, as ace3's module runs it, in ace3's dev container on the same files, timed from Python with its children's peak memory:

| File | Perl | Seconds | Peak memory |
|---|---|---|---|
| `big_90mb.vbe` | exit 0 | 24.77 | 8,805 MB |
| `escapes_90mb.vbe` | exit 0 | 18.54 | 8,322 MB |
| `high_90mb.vbe` | exit 0 | 11.82 | 8,322 MB |
| `no_end_90mb.vbe` | dies, `End marker not found` | 0.04 | 184 MB |

The Perl holds about 90 bytes for each byte of the file. In other runs while the VM was busy, the kernel killed it for memory (exit 137) on `big_90mb.vbe`, `escapes_90mb.vbe`, `high_90mb.vbe` and `markers_90mb.vbe`, after it had written part of its output. ace3's `run_tool` returns a killed process as finished, so the module then adds the part written as the decoded script, where ace4 adds all of it.

ace3's own modules through `tools/ace3/dumps/run_module.py`, one run each, including ace3's start: `vbscript_analyzer` on `hex_90mb.vbs` 6.8 s and on `runs_90mb.vbs` 9.1 s, and `nowhitespace_analyzer` on `mixed_90mb.rtf` 2.6 s, each with the result ace4 gives.
