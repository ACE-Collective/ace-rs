# Hostile PDFs

PLAN.md 4.9 asks what a crafted PDF can make libqpdf and the `pdf-parser.py` port do against a task's deadline and rlimits. The PDF module's limits are a 60 s deadline, 60 s of CPU and 2 GiB of address space (`crates/ace-mod-pdf/src/lib.rs`), plus the port's own bounds in `pdfparser::Limits`: 10 s, 64 MiB of output, 256 MiB for one decoded stream and 16 M tokens in one object.

`tools/samples/make-pdf-hostile` writes the set. Two commands measure it, once each, on 2026-11-07, on the dev container of `docs/measurements/build-loop.md`, with ace3's and budge's stacks idle on the same VM:

- **In a task.** `ACE_RS_PDF_HOSTILE=<dir> cargo test -p ace-pool --features test-pools --test supervisor measure_hostile -- --ignored --nocapture` submits each file to the real supervisor, with the module's limits, as `ace-rs-task`, under Landlock and seccomp. This is a debug build, with libqpdf at `-O0`, so its times are upper bounds. They start when the root is submitted and include the upload, and `ACE_RS_BUCKET_MEM_LIMIT=6g` kept the bucket up (below).
- **By part, optimized.** `pikepdf` (libqpdf and the reads) and `pdf-parser --task-limits`, from `cargo build --release -p ace-mod-pdf --bins`, each run once with `RLIMIT_AS` 2 GiB and `RLIMIT_CPU` 60 s, and `wait4`'s peak RSS. This is without containment. `pikepdf` also builds a JSON reply the task doesn't, so its peaks are upper bounds.

| File | Size | Task, debug | Task's end | Files out | libqpdf s | libqpdf peak MiB | Parser s | Parser peak MiB |
|---|---:|---:|---|---:|---:|---:|---:|---:|
| `annots_1m.pdf`: a million annotations on a page | 17 MB | 24.6 s | done | 2 | 7.46 | 2039, SIGABRT | 0.30 | 244 |
| `delimiters_64mib.pdf`: `(` to the end of the file | 67 MB | 2.5 s | done | 1 | 0.91 | 188 | 0.09 | 259 |
| `indirect_chain.pdf`: 100,000 references in a row | 2.9 MB | 1.7 s | done | 1 | 0.69 | 14 | 0.05 | 35 |
| `js_flate_1gib.pdf`: a script of 1 GiB | 1 MB | 3.3 s | **failed, SIGSEGV** | 0 | 1.37 | 1031, SIGSEGV | 0.03 | 261 |
| `js_flate_4gib.pdf`: a script of 4 GiB | 4.2 MB | 3.3 s | done | 1 | 0.95 | 1035 | 0.03 | 267 |
| `js_flate_twice_1gib.pdf`: the same through two filters | 2 KB | 3.3 s | **failed, SIGSEGV** | 0 | 1.52 | 1031, SIGSEGV | 0.03 | 260 |
| `length_loop.pdf`: a stream whose `/Length` is itself | 275 B | 0.1 s | done | 2 | 0.00 | 8 | 0.00 | 8 |
| `nested_arrays_1m.pdf`: a million `[` | 2 MB | 0.8 s | done | 1 | 0.00 | 8 | 0.14 | 162 |
| `nested_dicts_100k.pdf` | 700 KB | 0.1 s | done | 1 | 0.00 | 8 | 0.01 | 15 |
| `numbers_16mib.pdf`: `1 ` eight million times | 17 MB | 2.6 s | done | 1 | 0.00 | 8 | 0.43 | 255 |
| `object_streams_100k.pdf` | 444 KB | 0.2 s | done | 1 | 0.01 | 8 | 0.01 | 14 |
| `page_tree_deep.pdf`: 100,000 levels of `/Pages` | 7.2 MB | 2.8 s | done | 1 | 0.63 | 14 | 0.25 | 118 |
| `pages_200k.pdf` | 12 MB | 12.1 s | done | 1 | 3.65 | 691 | 0.38 | 248 |
| `stray_32mib.pdf`: `x ` outside any object | 34 MB | 2.4 s | done | 1 | 0.01 | 8 | 0.41 | 271 |
| `stream_flate_100mib.pdf`: 100 MiB in one stream | 98 KB | 1.1 s | done | 1 | 0.00 | 8 | 0.11 | 147 |
| `stream_lzw_quadratic.pdf`: LZW codes that each extend the last | 1.6 MB | 2.2 s | done | 1 | 0.00 | 8 | 0.66 | 263 |
| `xref_prev_loop.pdf` | 129 B | 0.1 s | done | 1 | 0.00 | 8 | 0.00 | 8 |

"Files out" counts what the result added; 0 means there was no result. Where libqpdf's time is 0.00 and its peak 8 MiB, it refused the file at once. The parser's peak includes the file itself.

What this shows:

- **Nothing reached the deadline or the CPU limit**, in either build. Parser runs end well inside its 10 s. libqpdf's worst here is 7.5 s optimized.
- **The address-space limit is what ends a decompression bomb, and the supervisor survives it.** A stream of more than about 2 GiB fails inside libqpdf's own buffer: `bad_alloc`, which libqpdf's C API catches and reports, so the block ends as a failed read does and the dump stays. A stream of about 1 GiB gets through that buffer and then `qpdf_oh_get_stream_data` calls `malloc` for its copy and doesn't check it, so the process takes SIGSEGV. The task fails with a row, and the supervisor leases the next one (`a_pdf_that_exhausts_a_task_leaves_a_row_and_the_supervisor_keeps_leasing`). That loses the dump as well, and a 2 KB file can cause it. ace3 would write the gigabyte. Avoiding the crash would mean decoding streams in Rust instead of libqpdf.
- **No C++ exception crossed into Rust.** Each comes back as an error from libqpdf's C API, and the two crashes above are a null pointer in C++, in a contained process.
- **Many annotations cost address space.** `qpdf_oh` handles live until the document closes, and a million annotations reach 2 GiB in the `pikepdf` side, which then aborts in an allocation. The task doesn't build that reply, and finished. A larger file would fail with a row.

## The bucket

With its default `ACE_RS_BUCKET_MEM_LIMIT` of 1 GiB, the dev stack's bucket was OOM-killed (exit 137) during this set, by uploads of tens of MB each, several times. The task then stays `running` while its upload fails. It was at 993 MiB after the set with a 6 GiB limit. So 256 MiB of output, the first limit tried here, became 64 MiB. The cause is outside this module, and any module that writes large files meets it, so it's reported to the plan rather than fixed here.
