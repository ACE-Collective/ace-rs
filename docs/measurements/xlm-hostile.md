# Hostile Excel 4.0 macros

PLAN.md 4.12 asks what a crafted macro can make the XLMMacroDeobfuscator port do against the pass timer and the module's limits. The module has a 75 s deadline, 75 s of CPU and 2 GiB of address space (`crates/ace-mod-xlm`), and gives each of its two passes 30 s.

A contained task can't use a signal to stop a pass, as 4.7 did, or a thread. So the interpreter reads its clock: every 256 steps of evaluation, and each loop a range can inflate (`FORMULA` over a range, `FOR.CELL`, `HLOOKUP`, `COUNTA`), and the parser every 4,096 tokens, and the readers on each record. A pass past its time, or past the output limit, is dropped, the file is tagged `xlmdeobfuscator_failed` or `xlmdeobfuscatorextractcells_failed`, and the next pass runs, which is ace3's outcome.

| What | Limit | When it's reached |
|---|---:|---|
| One pass's output | 256 MiB | the pass is dropped, as past its time |
| One string | 64 MiB | MemoryError in the macro, which ends its emulation and is printed |
| Text and cells a pass writes, cached formulas | 512 MiB | MemoryError |
| Cells copied by `IF` on an unknown condition | 64 M | MemoryError |
| All of a macro's `VirtualAlloc`s | 64 MiB | MemoryError |
| Tokens in one formula | 4 M | MemoryError |
| Elements in one XML part | 4 M | MemoryError |
| Python frames | 1000, counted | RecursionError, caught where Python's bare `except:` would catch it |
| Cells in a BIFF or XLSB sheet | 8 M | MemoryError (`ace-xlrd`, `ace-xlsb`) |

Python has none but the recursion limit and the timer; there a macro runs until memory or 30 s runs out. So each limit but the first is a place the port can stop earlier than ace3, and print `Error [...]:` where ace3 would have dropped the pass.

`tools/samples/make-xlm-hostile` writes the set. Two commands measure it, on 2026-11-07, on the dev container of `docs/measurements/build-loop.md`, with ace3's and budge's stacks idle.

- **The port, optimized:** `tools/library-diff`'s side, `target/release/xlmdeobfuscator`, both passes, one run each, under `RLIMIT_AS` 2 GiB. Peak is `ru_maxrss`, which holds both passes and the JSON the side writes.
- **In a task:** `ACE4_XLM_HOSTILE=<dir> cargo test -p ace-pool --features test-pools --test supervisor measure_hostile_xlm -- --ignored --nocapture`, a debug build in the real supervisor, one run each. That harness doesn't read the pool's stderr, so it stalls after eight files: the set was run in three parts.

| File | Port s | Port peak MiB | Task s, debug | Files out | `-f` | `-x` |
|---|---:|---:|---:|---:|---|---|
| `calls_deep.xlsm`: `A1()` in A1 | 0.00 | 8 | 0.3 | 2 | ends by its loop check | listed |
| `cells_150k.xlsm`: 150,000 cells | 0.41 | 140 | 4.2 | 2 | no formula to start at | 2.9 MiB |
| `chain_5000.xlsm`: 5,000 cells each reading the next | 2.83 | 20 | 25.3 | 2 | RecursionError caught, as Python | listed |
| `doubling.xlsm`: `B1&B1` in a loop | 0.51 | 710 | 68.0 | 2 | 128 MiB, MemoryError at 64 MiB | listed |
| `file_append.xlsm`: `FWRITE` of 100 KB in a loop | 0.22 | 264 | 5.6 | 1 | dropped: output | listed |
| `fill_range.xlsm`: 1,000 bytes into A2:IV65536 | 0.53 | 559 | 2.0 | 2 | MemoryError at 512 MiB | listed |
| `for_cell_huge.xlsm`: `FOR.CELL` over A1:IV65536, all empty | 1.87 | 13 | 18.1 | 2 | ends | listed |
| `for_cell_absurd.xlsm`: `ZZ999999`, which doesn't parse | 0.00 | 13 | 0.3 | 2 | parse error, as Python | listed |
| `goto_self.xlsm`: `GOTO(A1)` | 0.00 | 13 | 0.3 | 2 | ends by its loop check | listed |
| `one_formula_10mb.xlsm`: one `CALL` of 1.5 M arguments | 1.80 | 981 | 15.7 | 2 | 5.7 MiB | 5.7 MiB |
| `parens_100k.xlsm`: 100,000 nested parentheses | 0.09 | 60 | 1.1 | 2 | RecursionError | listed |
| `partial_if_copies.xlsm`: 2,000 `IF`s on an unknown cell | 0.05 | 44 | 0.5 | 2 | 0.3 MiB | listed |
| `rows_bomb.xlsm`: 240 MB of `<row/>` in 351 KB | 2.43 | 1043 | 11.2 | 2 | MemoryError at 4 M elements | the same |
| `run_ring.xlsm`: three `RUN`s in a ring | 0.00 | 11 | 0.2 | 2 | ends by its loop check | listed |
| `self_cell.xlsm`: `A1+1` in A1 | 0.00 | 11 | 0.3 | 2 | RecursionError caught | listed |
| `self_name.xlsm`: a name that is `loop&loop` | 30.00 | 330 | 38.1 | 1 | dropped: 30 s | listed |
| `virtual_alloc_16g.xlsm`: 16 GiB | 0.00 | 11 | 0.3 | 2 | MemoryError | listed |
| `virtual_alloc_many.xlsm`: 200 MB, repeatedly | 0.00 | 11 | 0.3 | 2 | MemoryError | listed |
| `while_big_lines.xlsm`: a `WHILE` printing long lines | 1.64 | 262 | 13.6 | 1 | dropped: output | listed |
| `while_true.xlsm`: `WHILE(1=1)` | 5.82 | 262 | 26.6 | 1 | dropped: output | listed |

What this shows:

- No file crashed a task, and each one ended in a file for the pass that can list cells, so the cell count and tags survive every macro here.
- The only macro that reached the 30 s clock is the exponential name. A macro that prints reaches the output limit first, in about 6 s here and about 27 s in a debug task, where Python took its 30 s (4.7: up to 81 MB). Both are the same outcome.
- The deepest peak is `rows_bomb.xlsm`, at 1,043 MiB with 2 GiB allowed. 4.7's Python hit MemoryError on a dense 9.8 MB sheet; the port has no dense matrix, and lists it.

Not measured: amd64. A macro that recurses to exactly Python's limit can stop a level or so away from where Python stops, because the port counts the frames of the functions it ports, and not of Python's small helpers such as `EvalResult.__init__`: 5 of 1,200 mutated files differed this way, each in how far a self-referencing cell's text is repeated before it's cut.
