# What yara-x recurses on, and the bounds a rule file is held to

7.16 found that one literal of about 3,000 escapes overflows the stack of yara-x's parser, which aborts the process (`yara-export.md`), and bounded the export. This is the same question for a rule file from the signatures repository, which reaches yara-x in the core's ruleset builder, `ace signatures check`, SVS validation's replay, the YARA pool's loader and `ace_yara::source`. `crates/ace-yara/src/guard.rs` holds the bounds, and these are the numbers they stand on.

Everything ran in the dev container (`docker compose exec -T dev`, Linux 6.18 on Rancher Desktop, 10 CPUs) on 2026-11-15, on yara-x and yara-x-parser 1.22.1 with logos 0.16.1, in a debug build of `ace-yara` unless a row says otherwise. A throwaway program compiled one crafted rule holding N of a construct, as the loader compiles it, on a thread of a given stack size, in a process of its own, and a script bisected N between the largest that returned and the smallest that died. The outcome is a crash or not and didn't vary between runs, so each N ran once. "Passes" is the largest N tried that returned; "dies" is the smallest that aborted with SIGABRT on a stack overflow. The two are at most a sixteenth apart.

## What overflows the stack

| N of | 1 MiB passes / dies | 2 MiB | 8 MiB | 64 MiB |
|---|---|---|---|---|
| escapes in one text string, meta string, string in a condition, regex or triple-quoted string (`\\`, `\"`, `\.`, `\x41`) | 1,216 / 1,280 | 2,432 / 2,560 | 9,728 / 10,240 | 81,920 / 86,016 |
| runs of `*` in one block comment (a comment of N lines that start ` * `) | 1,088 / 1,152 | 2,176 / 2,304 | 8,704 / 9,216 | 69,632 / 73,728 |
| U+00A0 in a row, where a space may be | | 2,432 / 2,560 | | |
| nested parentheses, `((((true))))` | 184 / 192 | 368 / 384 | 9,728 † / 10,240 | |
| `not` in a row; `-` and `~` are the same | 92 / 96 | 192 / 200 | 768 / 800 | |
| nested `for any i in (1..2) : (` | 68 / 72 | 136 / 144 | 9,728 † / 10,240 | |
| nested `with v = 1 : (` | 76 / 80 | 152 / 160 | 11,776 † / 12,288 | |
| nested `(true and ` | 76 / 80 | 160 / 168 | 640 / 672 | |
| nested `pe.sections[` | 44 / 46 | 92 / 96 | 384 / 400 | |
| nested `pe.sections[(- `, three levels each | | 64 / 68 | | |
| nested alternatives in a hex string, `( 06 | ` | 416 / 432 | 832 / 864 | 15,360 / 15,872 | |
| open parentheses that never close | 1,152 / 1,216 | 2,304 / 2,432 | 9,728 / 10,240 | |
| unclosed `( 01 | ` in a hex string | | 3,840 / 3,968 | | |

† It returned with no error and no rule: yara-x's own depth limit, below. An empty cell wasn't measured; the 64 MiB run was stopped after its first two rows.

2 MiB is a thread of the core's runtime, where the ruleset builds and where tests run. 8 MiB is a process's main thread, where `ace signatures check` and the contained replay compile.

Three places recurse. The lexer (logos' generated state machine) recurses once for each escape, each comment run and each multi-byte space: the first three rows. The parser is recursive descent and recurses for each bracket and unary operator. The compiler recurses over the tree it is given, which is why 96 indexes die where 384 parentheses do. `ace_yara::source`'s use of the parser alone, with no compile, dies at the same N for the lexer's rows and for parentheses, and later for the rest (`not` 1,536 / 1,600, `for` 272 / 288, an index 216 / 224 on 2 MiB).

yara-x has a limit of its own, 3,000 levels of syntax tree (`MAX_AST_DEPTH`), checked when the tree is built from the parse, after the parser has already recursed. On 64 MiB, 1,490 nested parentheses compile and 1,500 return with no error and no rule: `add_source` succeeds and the rule is silently missing. 2,990 `not` compile and 3,010 give no rule.

**Optimized.** With yara-x, yara-x-parser and logos at `opt-level = 3` and the rest of the build as it was (`--config profile.dev.package.<crate>.opt-level=3`), the lexer's three rows don't overflow at all: 1,048,576 of each compile on 1 MiB. The parser's and the compiler's still do: parentheses 368 / 384 on 2 MiB as before, `not` 1,472 / 1,536, an index 224 / 232. So the escape overflow that 7.16 found belongs to an unoptimized build, where the lexer's tail calls are real calls, and the nesting overflows to every build. A whole release build wasn't measured; the images run one.

## What didn't overflow

Each compiled, or was refused with an error, up to the N given on 2 MiB: `or`, `and` and `+` chains (262,144); alternatives, a class and bytes in a regex (262,144); groups nested in a regex (compile to 128 at least, then `invalid regular expression`, to 262,144); flat alternatives, bytes and jumps in a hex string (262,144); a chain of `a.a.a` (an error, 262,144); a rule that names the rule before it, 188,416 rules deep; a literal with no escape, an identifier, `//` comments, `/* x */` comments, CRLF, tags, metas and items of an `of` (65,536); unbalanced `{` and `}` (65,536).

## What costs time

Nested calls don't overflow: they take three times as long for each level, in the parser, which tries its alternatives again at each. `math.abs(math.abs(...1...))`, one run each:

| Levels | Debug | Optimized as above |
|---|---|---|
| 6 | 38 ms | |
| 8 | 195 ms | 29 ms |
| 10 | 1.85 s | 166 ms |
| 12 | 17.5 s | 1.35 s |
| 13 | 54.4 s | |
| 14 | over 60 s | 11.4 s, and then a syntax error |

`uint32(uint32(...))` costs the same (12 levels, 14.4 s), and so does the parser alone (12 levels, 34.6 s for `ace_yara::source`'s two parses). A compile of nothing takes about 15 ms, which the short times include. The cost is per expression: 1,000 expressions of six levels took 20.2 s, and 100 of eight levels 19.1 s.

## The bounds

| Bound | Limit | What dies on 2 MiB | Why this limit |
|---|---|---|---|
| escapes on one line (`MAX_ESCAPES`) | 1,024 | 2,560 | 7.16's bound for the export, kept |
| runs of `*` in a block comment | 1,024 | 2,304 | a comment of a thousand lines |
| spaces outside ASCII in a run | 1,024 | 2,560 | |
| open `(` and `[` and unary operators in a row, together (`MAX_NESTING`) | 32 | 96 of the costliest | a third of it |
| nested calls (`MAX_CALL_NESTING`) | 6 | time: 20 ms each | |

The lexer's frames sit on top of the parser's, so the worst case is every bound at once: 32 levels and a literal of 1,024 escapes at the deepest. `a_file_at_every_bound_fits_a_small_stack` compiles and parses each construct at its bound, and the mixes, on a 1.5 MiB thread in a debug build. No thread with a larger stack is used, since the contained replay may not start one.

What is left after the bounds: time is still linear in what a file holds. A file of 10,000 expressions of six nested calls takes minutes in a debug build, three times over (each file alone, then together), and the builder's limit doesn't stop a compile that is running.

## What the bounds refuse of real rules

`ace_yara::guard::check_file` over the signatures repository (102 rule files) and over ace3's `etc/` (42) refused none. The check read the files and wrote nothing.

What the number could include: the debug build's frames, which are larger than an optimized build's; one yara-x version; and the constructs tried, which are the ones yara-x's grammar nests. A construct that recurses and isn't a bracket, a unary operator, an escape, a comment run or a space isn't bounded, and none was found.
