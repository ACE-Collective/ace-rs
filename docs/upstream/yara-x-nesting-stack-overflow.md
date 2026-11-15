# Draft bug report for yara-x: stack overflow in the parser and the compiler on deep nesting

**Status: a draft. Not submitted anywhere, and nobody has been contacted.** The owner decides whether and where to send it. It is one of four reports that were first drafted as one: `yara-x-lexer-stack-overflow.md`, this one, `yara-x-rule-dropped-past-depth-limit.md` and `yara-x-nested-call-parse-cost.md`. `docs/measurements/yara-guard.md` has every measurement, and `crates/ace-yara/src/guard.rs` is how ace4 protects itself meanwhile.

---

## Title

Stack overflow (process abort) when compiling a rule with a few hundred levels of nesting, in optimized builds too

## Versions

- yara-x 1.22.1 and yara-x-parser 1.22.1, with logos 0.16.1, from crates.io.
- rustc 1.99.1, on Linux 6.18, aarch64.
- Not checked against a later release or against `main`.

## Summary

`yara_x::Compiler::add_source` overflows the thread's stack on a rule whose condition or hex pattern nests a few hundred levels deep. Rust can't catch that, so the process aborts with SIGABRT. Any program that compiles rules it didn't write, such as a service that builds a ruleset from a shared repository, can be taken down by one rule file.

Unlike the lexer's overflow (`yara-x-lexer-stack-overflow.md`), optimizing doesn't remove it: 384 nested parentheses abort a 2 MiB thread in a debug build and in a build with `yara-x`, `yara-x-parser` and `logos` at `opt-level = 3`.

## Reproducer

```rust
// Cargo.toml: yara-x = "=1.22.1"; cargo run, or cargo run --release
fn main() {
    let n = 400;
    let source = format!(
        "rule r {{ condition: {}true{} }}",
        "(".repeat(n),
        ")".repeat(n)
    );
    std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024) // Rust's default for a spawned thread
        .spawn(move || {
            let mut compiler = yara_x::Compiler::new();
            let _ = compiler.add_source(source.as_bytes());
        })
        .unwrap()
        .join()
        .unwrap();
}
```

The other constructs, each with N of it:

```text
rule r { condition: not not not ... true }                                  // also - and ~
rule r { condition: for any i0 in (1..2) : ( for any i1 in (1..2) : ( ... true ) ) }
import "pe" rule r { condition: pe.sections[pe.sections[ ... 0 ].raw_data_size].raw_data_size == 0 }
rule r { strings: $a = { 01 02 03 04 ( 06 | ( 06 | ... 05 ) ) } condition: $a }
```

**Expected:** an error such as "expression nested too deeply", or the rule compiles.

**Actual:** the process aborts (SIGABRT, exit status 134) after printing

```text
thread '<unknown>' has overflowed its stack
fatal runtime error: stack overflow, aborting
```

## Measurements

On a 2 MiB thread, the largest N that returned and the smallest that aborted, with this reproducer's `Compiler::new()`:

| N of | Debug | `yara-x`, `yara-x-parser`, `logos` at `opt-level = 3` |
|---|---|---|
| nested `(` ... `)` | 368 / 384 | 368 / 384 |
| `not` in a row | 192 / 200 | 1,472 / 1,536 |
| nested `for any i in (1..2) : (` | 136 / 144 | 264 / 272 |
| nested `pe.sections[` | 96 / 100 | 224 / 232 |
| nested `( 06 | ` in a hex pattern | 832 / 864 | 5,120 / 6,144 |

A nested hex pattern that returns doesn't always compile: from 256 levels it is `error[E014]: invalid regular expression`, and in the optimized build from 1,536 levels `add_source` returns `Ok` with no rule (`yara-x-rule-dropped-past-depth-limit.md`).

By stack size, debug build (from `docs/measurements/yara-guard.md`, where each rule compiles as ace4's loader compiles it, with four globals defined, which costs a little more stack: an index aborts at 96 there):

| N of | 1 MiB | 2 MiB | 8 MiB |
|---|---|---|---|
| nested `(` ... `)` | 184 / 192 | 368 / 384 | 9,728 (no rule past 1,499) / 10,240 |
| `not` in a row (`-` and `~` are the same) | 92 / 96 | 192 / 200 | 768 / 800 |
| nested `for any i in (1..2) : (` | 68 / 72 | 136 / 144 | 9,728 (no rule) / 10,240 |
| nested `(true and ` | 76 / 80 | 160 / 168 | 640 / 672 |
| nested `pe.sections[` | 44 / 46 | 92 / 96 | 384 / 400 |
| nested `( 06 | ` in a hex pattern | 416 / 432 | 832 / 864 | 15,360 / 15,872 |
| `(` that never close (a syntax error) | 1,152 / 1,216 | 2,304 / 2,432 | 9,728 / 10,240 |

The parser alone, `Parser::new(source).try_into_cst()`, returns at 384 parentheses, 200 `not` and 96 indexes on 2 MiB in a debug build: the overflow at those depths is past the CST, where the AST is built and compiled.

## Likely cause

`ParserImpl` is recursive descent with no depth check, the AST is built from its events by recursive functions, and the compiler recurses over the AST. `MAX_AST_DEPTH` (3,000, `parser/src/ast/cst2ast.rs`) is checked when the AST is built, after the parser has recursed, and is itself more than a 2 MiB stack holds: the compiler's recursion over the AST dies at about 100 nested indexes.

## Suggested direction

Count depth in the parser itself (where `begin` and `end` bracket a production) and report an error past a limit that fits the default thread stack with the compiler's recursion in mind. A few hundred levels is far more than rules use. Alternatively grow the stack on demand with something like the `stacker` crate around the recursive functions of the parser and the compiler.

## Confirmed

Re-run on 2026-11-15 on yara-x 1.22.1 (the only version in the local cargo registry; no later release was fetched to check). Each case ran in a process of its own, on a 2 MiB thread, so an abort took nothing else down.

- Debug: every row of the first table, both numbers. The reproducer's 400 parentheses aborted.
- Optimized as the table's heading says: every row, both numbers.
