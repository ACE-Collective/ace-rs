# Batch 4's HTML modules against crafted files

PLAN.md 7.5: a contained parser task is one thread with no exec, so each module is bounded for hostile input, and what crafted input costs it is measured against its limits. The four modules have the default 300 s, 1 GiB and 300 CPU seconds; ace3 gives them its default `maximum_analysis_time` of 60 s. What bounds each:

- `html_data_url_extraction` reads at most `max_bytes` (100 MiB), as ace3 does, and writes at most 500 files.
- `mhtml` writes at most 500 parts. Python's feed parser raises `RecursionError` on a file nested past 974 multiparts in ace3 (past 973 since ace3's `5ca91195` added a frame under every module, measured at `c55f15a2`); the port raises it at the same depth, without recursing.
- `html_js_extraction` parses the whole file, as ace3 does, into BeautifulSoup's tree, which `ace_lxml::soup` keeps flat, in document order, so no depth of nesting recurses. It writes at most 500 scripts and adds at most 500 URLs and 500 URI paths. Each document's DOM snapshot stops at 2,000 elements and 512 KiB, 16 KiB an attribute and 4 KiB a text, as ace3's does, and a result keeps at most 16 MiB of snapshots.
- `har_extraction` parses at most `max_file_size` (50 MiB) of JSON, as ace3 does, and extracts at most `max_extracted_files` (50) bodies.

The 500s are ace3's `maximum_observable_count` for files and URLs in a root, which ace-rs's core doesn't have: past them ace3 keeps decoding and writing files to its node that no observable holds.

Measured on 2026-11-09 on the dev container of `build-loop.md` (Rancher Desktop, 10 CPUs), with ace3's and budge's stacks up.

## Command

`tools/samples/make-html-hostile <dir>` writes the files. In the dev container:

    ACE_RS_HTML_HOSTILE=<dir> ACE_RS_HTML_MODULE=<module> cargo test -p ace-pool --features test-pools \
        --test supervisor measure_html -- --ignored --nocapture

submits each file whose name starts with the module's to the real supervisor, which runs the module, and `file_type` first for `html_js_extraction` and `mhtml`, which wait for it, as `ace-rs-task` under Landlock and seccomp with their limits. 3 runs each, each in a new root under a new name. The time runs from the root's submission to the end of the module's task on the file, so it includes the upload, the lease, the task process's start, file_type's task where there is one, and the uploads of the module's files. The tasks the files a run writes queue, such as file_type's for each script, finish before the next run starts, and aren't counted. It's a dev build, unoptimized but for the crates `Cargo.toml` raises.

The stack's bucket, held to 1 GiB, was killed once (exit 137) while the runs wrote hundreds of megabytes into it, so it was restarted before each module's runs. That's the test stack's limit, not the module's.

## Results

| File | Size | Module | End | Files | Seconds, 3 runs |
|---|---|---|---|---|---|
| `huge_100mb.html`: one data URL of 93 MB of base64 | 104,857,594 | html_data_url_extraction | done | 1 of 70 MB | 1.30 to 1.82 |
| `many_10mb.html`: 238,312 data URLs | 10,009,104 | html_data_url_extraction | done | 500 | 2.73 to 3.23 |
| `no_slash_10mb.txt`: `data:` and 10 MB with no `/` | 10,485,765 | html_data_url_extraction | done | 0 | 0.10 to 0.31 |
| `prefixes_10mb.txt`: `data:a/b` repeated | 10,485,760 | html_data_url_extraction | done | 0 | 0.16, 0.16, 0.16 |
| `parts_10mb.mht`: 174,762 parts | 8,277,537 | mhtml | done | 500 | 2.94 to 2.99 |
| `nested_974.mht`: multiparts 974 deep | 62,149 | mhtml | done | 1 | 0.31, 0.31, 0.31 |
| `nested_100000.mht`: 100,000 deep | 6,966,822 | mhtml | done, no result | 0 | 0.31, 0.31, 0.31 |
| `base64_40mb.mht`: one base64 part | 42,495,125 | mhtml | done | 1 | 1.61 to 1.67 |
| `scripts_10mb.html`: 262,144 inline scripts | 9,739,252 | html_js_extraction | done | 500 | 4.53 to 5.13 |
| `handlers_10mb.html`: 262,144 `onclick` handlers | 11,423,226 | html_js_extraction | done | 500 | 4.74 to 4.80 |
| `external_10mb.html`: 291,271 relative script sources | 10,374,646 | html_js_extraction | done | 0, 500 URI paths | 1.91 to 1.96 |
| `urls_10mb.html`: 201,649 script URLs, each a host of its own | 11,181,234 | html_js_extraction | done | 0, 500 URLs | 1.78 to 1.84 |
| `elements_10mb.html`: a script and 1,310,720 elements | 10,485,801 | html_js_extraction | done | 1 | 1.93 to 2.12 |
| `deep_100000.html`: a script in 100,000 nested `<div>`s | 1,100,037 | html_js_extraction | done | 1 | 0.41 to 0.47 |
| `attrs_10mb.html`: one element with 524 attributes of 20,000 characters | 10,484,131 | html_js_extraction | done | 1 | 0.62 to 0.64 |
| `pages_20mb.mht`: 2,000 HTML parts, each a script and 30 elements | 19,144,961 | html_js_extraction | done | 500 | 4.01 to 4.12 |
| `entries_45mb.har`: 142,987 pages | 49,966,271 | har_extraction | done | 50 | 1.20 to 1.26 |
| `body_40mb.har`: one page of 40 MB | 41,943,228 | har_extraction | done | 1 | 1.05 to 1.16 |
| `scripts_20mb.har`: 49 pages of 20,000 script sources each | 37,482,125 | har_extraction | done | 50 | 3.39 to 3.54 |
| `nested_1mb.har`: arrays a million deep | 2,097,161 | har_extraction | done | 0 | 0.10 to 0.16 |

File names are the module's name and these. Every task ended `done`, well inside its deadline. What each file does:

- `huge_100mb.html` decodes 93 MB of base64 into one 70 MB file.
- `many_10mb.html` stops at its 500th file. ace3 would decode and write all 238,312, and add the first 500 as observables, each `add_observable` scanning every observable the root holds.
- `no_slash_10mb.txt` and `prefixes_10mb.txt` start matches that can't finish. The regex crate's search is linear in the text. Python's isn't for `prefixes`: from each `data:a/` its `[^;]+` runs to the end of the text and backs off a byte at a time, so ace3's `findall` took 3.87 s on 128 KiB, 15.45 s on 256 KiB and 61.61 s on 512 KiB of it (one run each, in ace3's dev container), past its 60 s on half a megabyte. `no_slash` takes Python 0.01 s for 10 MB.
- `nested_100000.mht` raises `RecursionError` at depth 975 in both, so there's no result, and the port doesn't recurse to find that out. `parts_10mb.mht` parses 174,762 parts in about 0.5 s and writes the first 500.
- `scripts_10mb.html`, `handlers_10mb.html` and `pages_20mb.mht` count every script and handler, dedupe each by its SHA-256 and write the first 500, each with its document's snapshot: one snapshot for the first two, and for the third one per part, kept in the result only for the 500 parts whose scripts were written. A snapshot is kept at its first sidecar, so documents with no script written don't use the 16 MiB. `external_10mb.html` and `urls_10mb.html` stop at 500 observables; ace3 has no limit on URI paths and would add all 291,271.
- `elements_10mb.html`'s snapshot stops at 2,000 elements, and `attrs_10mb.html`'s cuts each attribute to 16 KiB and stops at 512 KiB of JSON, counted without building the JSON. `deep_100000.html` is 100,000 elements deep in the tree, with no recursion.
- `entries_45mb.har` is just under `max_file_size`. `ace-pycompat`'s `json.loads` reads it, 142,987 pages are deduplicated by hash, and the first 50 written. `scripts_20mb.har` resolves 980,000 script sources against their pages, and the one script two pages load gets the first page's snapshot.
- `nested_1mb.har` is past the JSON decoder's recursion limit, so the result is ace3's `not valid JSON` error, with `ace-pycompat`'s fixed message where Python's names the stack it used.
