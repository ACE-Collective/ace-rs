# The YARA export of the detections: what a hostile list costs

PLAN.md 7.16 turns the observables enabled for detection into YARA rules (`crates/ace-yara/src/export.rs`). Their values are text an analyst typed, so the export is bounded, and these are the numbers the bounds stand on. Everything ran in the dev container (`docker compose exec -T dev`, Linux 6.18 on Rancher Desktop, 10 CPUs) on 2026-11-15, in a debug build of `ace-yara` on yara-x 1.22.1, which is the slowest build the code runs in. A release build wasn't measured.

## A literal with many escapes overflows the compiler's stack

yara-x's parser recurses once for each escape sequence in one literal. Enough of them overflow the thread's stack, which aborts the process: nothing can catch it. It is per literal, not per file: 100,000 escapes spread over 1,000 strings compile.

A throwaway test compiled one rule with one string holding N escapes, on a thread of a given stack size, one run of each (the outcome is a crash or not, and didn't vary):

| The literal | Stack | Compiles up to | Overflows at |
|---|---|---|---|
| a text string of N `\\` | 2 MiB | 2,500 | 3,000 |
| a text string of N `\"` | 2 MiB | 2,500 | 3,000 |
| a regex of N `\.` | 2 MiB | 2,500 | 3,000 |
| a regex of N `\xNN` | 2 MiB | 2,500 | 3,000 |
| a text string of N `\\` | 64 MiB | 32,000 | 100,000 |
| 1,000 text strings of 100 `\\` each | 2 MiB | 100,000 in all | not reached |

2 MiB is what a blocking thread of the core's runtime has, where the ruleset builds. So one string holds at most `MAX_ESCAPES`, 1,024: under half of what a debug build takes. A value of 4,096 backslashes, which a list accepts, would otherwise take the core down at its next ruleset build. `a_value_of_escapes_can_t_overflow_the_compiler_s_stack` runs the bound on a 2 MiB stack.

What the number could include: only the debug build's frames, which are larger than a release build's, so a release build overflows later, not sooner. It wasn't measured against another yara-x version.

## Generating the largest export

`cargo test -p ace-yara --lib export -- --nocapture`, three runs. `the_export_is_bounded` generates the export of 1,000 detections of 4,096 bytes each, the most a list holds. 675 fit `MAX_SOURCE_BYTES` (8 MiB), as 8,354,159 bytes of rules, and the rest are reported.

| | Median | Range |
|---|---|---|
| `generate`, which compiles the type's rule once and the namespace once | 19.87 s | 19.71 to 19.89 s |

The ruleset's own build then compiles the same files twice more (each alone, then together), so the largest export adds about 40 s to a build in a debug binary, against a build's limit of 600 s (`ace_core::rulesets::BUILD_TIMEOUT`). A compile of one small rule takes about 17 ms (20 compiles in 327 to 334 ms, two runs), which is what checking each detection alone costs when a type's rule doesn't compile whole: about 17 s for 1,000.

What the number could include: the test binary's other tests running beside it on other threads, and a warm page cache. Nothing was skipped: every one of the 675 compiled.

## What yara-x made of ace3's templates and strings

Every template in ace3's `etc/yara_templates` compiles under yara-x 1.22.1 with no warning, and so does every string shape the export writes: text strings with `ascii wide nocase fullword`, and the bounded regexes for ASCII and for UTF-16, with their `(^|...)` and `(...|$)` boundaries and `\x00` bytes. yara-x rejected none. A character outside ASCII in a regex is written as it is, as ace3 writes it, and yara-x matches its UTF-8 bytes with no case folding outside ASCII, as libyara does.
