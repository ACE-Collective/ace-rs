# Hostile Office and RTF files

PLAN.md 4.10 asks what a crafted file can make the olevba and rtfobj ports do against a task's deadline and limits. Both modules run with a 60 s deadline, 60 s of CPU and 2 GiB of address space (`crates/ace-mod-oletools/src/lib.rs`), single-threaded, with no temporary files, under Landlock and seccomp. The port's own limits, each of which raises MemoryError where Python would carry on until memory ran out:

| What | Limit | Where |
|---|---:|---|
| One OLE stream read | 256 MiB | `ole.rs` |
| One VBA stream decompressed | 256 MiB | `vba.rs` |
| One zip member, ActiveMime or PowerPoint storage | 256 MiB | `pyzip.rs`, `olevba.rs`, `ppt.rs` |
| A file's macros | 64 MiB, 4096 files | `olevba.rs` |
| One p-code dump | 64 MiB | `pcode.rs` |
| RTF objects | 65,536, 256 MiB decoded | `rtf.rs` |
| RTF report | 64 MiB | `rtf.rs` |
| RTF saved files | 4096, 64 MiB | `rtf.rs` |

`tools/samples/make-oletools-hostile` writes the set. Three commands measure it, once each, on 2026-11-07, on the dev container of `docs/measurements/build-loop.md`, with ace3's and budge's stacks idle on the same VM:

- **In a task.** `ACE_RS_OLETOOLS_HOSTILE=<dir> cargo test -p ace-pool --features test-pools --test supervisor measure_hostile_oletools -- --ignored --nocapture` submits each file to the real supervisor, with the module's limits, as `ace-rs-task`. This is a debug build, so its times are upper bounds. They start when the root is submitted and include the upload, and `ACE_RS_BUCKET_MEM_LIMIT=6g` kept the bucket up (`docs/measurements/pdf-hostile.md`).
- **The port, optimized.** The `olevba` and `rtfobj --task-limits` binaries from `cargo build --release -p ace-mod-oletools --bins`, each run once with `RLIMIT_AS` 2 GiB and `RLIMIT_CPU` 60 s, and `wait4`'s peak RSS. No containment. These also build a JSON reply the task doesn't, so the peaks are upper bounds.
- **The library.** oletools 0.60.2 through its adapter on the `python-libraries` image, under a 70 s kill and an 8 GiB container, which is what ace3's 60 s would be near, with no rlimit, because ace3 has none. Its peak includes Python and the imports, 358 MiB where XLMMacroDeobfuscator loads.

| File | Size | Task, debug | Task's end | Files out | Port s | Port peak MiB | Port raised | The library |
|---|---:|---:|---|---:|---:|---:|---|---|
| `attribut_storm.doc`: a stream of 4 MB of `\0Attribut` hits, each a stream to the end | 3.9 MiB | 0.2 s | done | 2 | 0.04 | 16 | - | 22.01 s, 59 MiB |
| `deep_directory.doc`: 20,000 siblings in one chain | 3.8 MiB | 0.1 s | done | 0 | 0.02 | 12 | RecursionError | 0.16 s, 56 MiB |
| `difat_loop.doc`: a DIFAT sector naming itself, 16 M times | 0.0 MiB | 60.1 s | failed **the task process was killed by SIGXCPU (** | 0 | 5.71 | 8 | AttributeError | 70.01 s, 159 MiB, **killed** |
| `directory_cycles.doc`: 20,000 entries whose links go round | 3.8 MiB | 0.1 s | done | 0 | 0.02 | 11 | RecursionError | 0.17 s, 56 MiB |
| `fat_loop_4gib.doc`: a stream of 4 GiB on a FAT loop | 0.0 MiB | 0.1 s | done | 0 | 0.02 | 259 | MemoryError | 5.03 s, 8178 MiB, **killed** |
| `mini_loop.doc`: the same in the mini FAT | 0.0 MiB | 0.1 s | done | 0 | 0.02 | 8 | - | 0.21 s, 43 MiB |
| `mso_bomb_2gib.doc`: ActiveMime of 2 GiB in Word 2003 XML | 2.7 MiB | 0.1 s | done | 0 | 0.83 | 266 | - | 3.68 s, 6204 MiB |
| `nested_multipart.doc`: MIME multiparts nested 2 MB deep | 1.9 MiB | 0.1 s | done | 0 | 0.04 | 17 | - | 6.73 s, 61 MiB |
| `nested_storages.doc`: 900 nested storages | 0.1 MiB | 0.1 s | done | 0 | 0.02 | 22 | RecursionError | 0.14 s, 44 MiB |
| `ppt_many_storages.ppt`: 161,161 storages in a PowerPoint stream | 3.9 MiB | 18.6 s | done | 4096 | 0.06 | 93 | MemoryError | 13.49 s, 839 MiB |
| `ppt_zlib_bomb_1gib.ppt`: a compressed storage of 1 GiB | 1.0 MiB | 4.4 s | done | 0 | 0.80 | 260 | MemoryError | 5.57 s, 2101 MiB |
| `rtf_bin_64mib.rtf`: `\bin0` 13 M times in an objdata | 64.0 MiB | 2.5 s | done | 1 | 0.33 | 66 | - | 11.17 s, 87 MiB |
| `rtf_bin_hex_256mib.rtf`: `\bin` of 128 MiB in an objdata | 128.0 MiB | 12.3 s | done | 0 | 4.47 | 770 | MemoryError | 1.51 s, 790 MiB |
| `rtf_braces_64mib.rtf`: `{` 64 M times | 64.0 MiB | 0.6 s | done | 0 | 0.10 | 66 | - | 20.06 s, 358 MiB |
| `rtf_destinations_64mib.rtf`: `\objdata` 7.5 M times | 64.0 MiB | 19.0 s | done | 4096 | 0.19 | 135 | MemoryError | 70.08 s, 2886 MiB, **killed** |
| `rtf_hex_128mib.rtf`: one object of 128 MiB of hex | 128.0 MiB | 4.6 s | done | 1 | 0.54 | 450 | - | 1.07 s, 470 MiB |
| `rtf_objects_1mib.rtf`: 47,662 small objects | 1.0 MiB | 19.4 s | done | 4096 | 0.15 | 115 | MemoryError | 19.72 s, 358 MiB |
| `rtf_objects_64mib.rtf`: 3 M small objects | 64.0 MiB | 21.5 s | done | 4096 | 0.21 | 135 | MemoryError | 70.05 s, 1512 MiB, **killed** |
| `rtf_quote_64mib.rtf`: `\'` 13 M times in an objdata | 64.0 MiB | 2.6 s | done | 1 | 0.11 | 66 | - | 15.94 s, 358 MiB |
| `text_base64.doc`: source code, 4 MB of base64 strings | 3.9 MiB | 2.0 s | done | 1 | 0.09 | 32 | - | not measured |
| `text_dots_no_at.doc`: source code, 4 MB of `a.` | 3.9 MiB | 2.2 s | done | 1 | 0.10 | 32 | - | 70.02 s, 358 MiB, **killed** |
| `text_hex.doc`: source code, one hex string of 4 MB | 3.9 MiB | 2.3 s | done | 1 | 0.08 | 50 | - | 13.34 s, 358 MiB |
| `text_keywords.doc`: source code, 4 MB of keywords | 3.9 MiB | 1.6 s | done | 1 | 0.07 | 65 | - | 9.57 s, 358 MiB |
| `text_many_hex.doc`: source code, 4 MB of hex strings | 3.9 MiB | 2.3 s | done | 1 | 0.10 | 65 | - | 11.90 s, 358 MiB |
| `text_non_ascii.doc`: source code, 4 MB of Cyrillic | 3.9 MiB | 1.7 s | done | 1 | 0.08 | 65 | - | 7.34 s, 358 MiB |
| `text_underscores.doc`: source code, 4 MB of `a_` | 3.9 MiB | 1.5 s | done | 1 | 0.06 | 65 | - | 12.05 s, 358 MiB |
| `text_urls.doc`: source code, 4 MB of URLs | 3.9 MiB | 2.0 s | done | 1 | 0.09 | 30 | - | 12.38 s, 358 MiB |
| `vba_bomb.doc`: a module of 4 MB that decompresses to about 40 MB | 3.9 MiB | 11.5 s | done | 1 | 0.51 | 225 | - | 62.37 s, 1138 MiB |
| `xml_deep.doc`: 500,000 nested elements | 3.4 MiB | 0.1 s | done | 0 | 0.09 | 143 | - | 0.30 s, 358 MiB |
| `xml_laughs.doc`: an XML entity bomb | 0.0 MiB | 0.1 s | done | 0 | 0.07 | 11 | - | 0.21 s, 358 MiB |
| `zip_bomb_3gib.docm`: an OLE member of 3.7 GiB in 4 MB of zip | 3.7 MiB | 2.5 s | done | 0 | 0.80 | 263 | MemoryError | 4.52 s, 7657 MiB |
| `zip_many_members.docm`: 1,500 OLE members | 0.8 MiB | 6.7 s | done | 1500 | 0.06 | 20 | - | 1.22 s, 358 MiB |

"Files out" counts what the result added. A task in 0.1 s with no files was one of three things. `mso_bomb_2gib.doc`, `nested_multipart.doc`, `xml_deep.doc` and `xml_laughs.doc` are `text/plain` to libmagic, and ace3's own check skips that, so only the two columns outside the task read them. The directory cases raise RecursionError, as the library does on the same frame (`ole.rs` counts them, and `ole_deep_directory.doc` is a sample).

What this shows:

- **Only one reached a deadline, and only in the debug build.** `difat_loop.doc` takes 5.8 s optimized, because it visits 2 billion sectors of one 4 KB file, and over 60 s at `-O0`. The library doesn't finish it in 70 s. Nothing else passes 21.4 s in a task, or 5 s optimized.
- **Nothing here gets as far as the address-space limit.** The worst peak is 770 MiB, on `rtf_bin_hex_256mib.rtf`, which then stops at the 64 MiB of saved files. No file aborted or crashed the task process. An earlier version without the object count did: `rtf_destinations_64mib.rtf` reached 2 GiB and SIGABRT at about 7 M objects.
- **The limits change what a task finishes.** On `fat_loop_4gib.doc` the library grows until its 8 GiB container kills it, and the port raises at 256 MiB. A zip or ActiveMime bomb past 256 MiB gets MemoryError where the library reads it and goes on.
- **A limit is a way to hide.** 4096 decoy macros, or objects, before the real one means the real one isn't extracted. The result is `olevba_failed` with the sandbox directive under an Office extension, or `return_code` 1 with `MemoryError` in `stderr`, and what came first is kept. ace3 has no such limit, and in ace3 such a file costs 161,161 file observables (`ppt_many_storages.ppt`) or reaches its deadline.

## Further than ace3 would get

Rust's speed moves some files from the library's deadline into a result, which is more than ace3 gives:

- `text_dots_no_at.doc` takes the library over 70 s, in its e-mail pattern's backtracking, and the port 0.1 s.
- `rtf_objects_64mib.rtf` and `rtf_destinations_64mib.rtf` reach ace3's kill, with Python's `data +=` and up to 2.9 GiB. The port gets 4096 files of them.
- `vba_bomb.doc` takes the library 62 s, past ace3's 60 s, with Python's byte-at-a-time decompression. The port takes 0.5 s and keeps the macro.
- `rtf_quote_64mib.rtf` costs the library 16 s, in its `re.sub` on each `\\'`. The port only filters what's new, and takes 0.1 s.

On every file both finish without a limit of the port's, they give the same output: checked by comparing the replies for `attribut_storm.doc`, `text_urls.doc`, `text_hex.doc` and `rtf_bin_hex_256mib.rtf` run without limits.

## Why not the cfb crate

PLAN.md 4.10 says onto the cfb crate. cfb is kept up (mdsteele/rust-cfb; 0.16.0 is from 2026-10-31, 0.15.0 from 2026-09-18, and crates.io counts 31 M recent downloads). But 0.16.0 refuses what olefile opens: of the `ole_*` samples, a bad DIFAT, a bad directory start, an odd name length, a sector shift other than 9, a directory loop and a truncated file are errors at open, where olefile reports each as a defect and keeps reading, and olevba finds macros in several. It has no way to reach olefile's orphaned directory entries either, where olevba looks for macro source. So `ole.rs` is a port of olefile, and nothing here uses cfb.
