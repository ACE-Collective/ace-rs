# Batch 2's modules against crafted files

PLAN.md 7.5: a contained parser task is one thread with no exec, so each module is bounded for hostile input, and what crafted input costs it is measured against its limits. `file_type` has 300 s and 2 GiB of address space (ace3 gives it no limit, and its `file` and node none either); `dhash` 300 s and 2 GiB; the others have the default 300 s and 1 GiB. The JavaScript check's own measurements are in `javascript-check.md`.

Measured on 2026-11-09 on the dev container of `build-loop.md` (Rancher Desktop, 10 CPUs), with ace3's and budge's stacks up.

## Command

`tools/samples/make-identity-hostile <dir>` writes the files. In the dev container:

    ACE4_FILES_HOSTILE=<dir> ACE4_FILES_MODULE=<module> cargo test -p ace-pool --features test-pools \
        --test supervisor measure_file_identity -- --ignored --nocapture

submits each file whose name starts with the module's to the real supervisor, which runs `file_type` and the module as `ace4-task` under Landlock and seccomp with their limits. 3 runs each, each in a new root under a new name. The time runs from the root's submission to the module's task's end, so it includes the upload, the lease, the task process's start and, for a module that depends on file_type, file_type's task. It's a dev build, with oxc at `opt-level = 3` and the rest of the task unoptimized.

## Results

| File | Size | Module | End | Seconds, 3 runs |
|---|---|---|---|---|
| `file_type_parens_10mb.js`: 10 MB of `(` | 10,485,768 | file_type | done | 0.26, 0.26, 0.26 |
| `file_type_arrows_1mb.js`: 349,525 nested arrows | 1,048,576 | file_type | done | 0.15 to 0.21 |
| `file_type_minified_8mb.js`: ordinary code | 8,155,560 | file_type | done | 0.41 to 0.47 |
| `file_type_minified_2mb.js`: the same, parsed | 2,038,890 | file_type | done | 0.26, 0.26, 0.26 |
| `file_type_zip_65535.zip`: 65,535 members | 6,269,162 | file_type | done | 0.21 to 0.27 |
| `file_type_headers_20mb.txt`: 1.5 million header lines | 20,971,541 | file_type | done | 0.73 to 0.78 |
| `file_type_text_100mb.txt` | 104,857,588 | file_type | done | 0.21, 0.21, 0.21 |
| `file_type_labels_20mb.pem`: 343,000 empty certificate blocks | 20,621,975 | file_type | done | 0.57, one run |
| `x509_analyzer_labels_20mb.pem`: the same | 20,621,975 | x509_analyzer | done | 0.63 to 0.68 |
| `lnk_parser_blocks_10mb.lnk`: 655,000 extra data blocks | 10,485,844 | lnk_parser | done | 0.52, 0.52, 0.52 |
| `dhash_13000x13000.png`: 169 million pixels, with `dhash` | 197,910 | dhash | done | 0.73 to 0.74 |
| `dhash_bomb.png`: a 20000 by 20000 header | 2,000 | dhash | done | 0.15 to 0.27 |

Every task ended `done`, well inside its deadline. What each file does:

- The parentheses pass V8's nesting limit, so the bracket count refuses them before oxc parses (`MAX_NESTING`), as node refuses them.
- The arrows and the 8 MB file could need more than the 1 GiB stack the parse may have (`MAX_STACK`), so the JavaScript check fails without parsing. node refuses the arrows (its stack) and accepts the 8 MB file: that file isn't marked `type=script.javascript` in ace4. The 2 MB file parses, on a 0.68 GiB stack it reserves and barely touches.
- The zip check reads the central directory once (`ace-mod-oletools`' `zipfile` port); the email check stops at the end of the file, having found only two of the three headers.
- The text is read whole by the checks, then libmagic reads its start.
- No block holds a certificate, so `is_x509` is false and `x509_analyzer` skips the file.
- LnkParse3's port reads each extra block once; its own bounds are in `crates/ace-lnkparse`.
- dhash runs with the fixture reference images, `tools/ace3/dumps/fixtures/dhash/analyst_data/dhash` (`measure_file_identity` sets `source_dir` to it). The 169-million-pixel image is under Pillow's bomb limit, so it decodes, one byte a pixel, and resizes; the bomb is past the limit, so it isn't an image and the module skips it, as ace3's `is_image` is false for it. ace-dhash and image-webp build at `opt-level = 3` in dev.
