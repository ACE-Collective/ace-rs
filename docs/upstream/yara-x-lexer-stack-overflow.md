# Draft bug report for yara-x: stack overflow in the lexer on many escapes in one literal

**Status: a draft. Not submitted anywhere, and nobody has been contacted.** The owner decides whether and where to send it. It is one of four reports that were first drafted as one: this one, `yara-x-nesting-stack-overflow.md`, `yara-x-rule-dropped-past-depth-limit.md` and `yara-x-nested-call-parse-cost.md`. `docs/measurements/yara-guard.md` has every measurement, and `crates/ace-yara/src/guard.rs` is how ace4 protects itself meanwhile.

---

## Title

Stack overflow (process abort) when lexing a literal with a few thousand escape sequences, in a build where `yara-x-parser` and `logos` aren't optimized

## Versions

- yara-x 1.22.1 and yara-x-parser 1.22.1, with logos 0.16.1, from crates.io.
- rustc 1.99.1, on Linux 6.18, aarch64.
- Not checked against a later release or against `main`.

## Summary

In a debug build, `yara_x::Compiler::add_source` and `yara_x_parser::Parser` overflow the thread's stack on a rule that holds one literal with about 2,500 escape sequences. Rust can't catch that, so the process aborts with SIGABRT. The rule is valid. The same happens for a block comment with about 2,300 runs of `*`, and for about 2,500 U+00A0 in a row where a space may be.

It doesn't happen when `yara-x`, `yara-x-parser` and `logos` are built at `opt-level = 3`. So it affects debug builds, test suites among them, and any build that doesn't optimize those crates.

## Reproducer

```rust
// Cargo.toml: yara-x = "=1.22.1"; a debug build (cargo run)
fn main() {
    let source = format!(
        "rule r {{ strings: $a = \"{}\" condition: $a }}",
        "\\\\".repeat(3000)
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

The rule is one string of 3,000 `\\`. The same happens with `yara_x_parser::Parser::new(source.as_bytes()).try_into_cst()` and no compiler.

**Expected:** the rule compiles (it is valid), or an error is returned.

**Actual:** the process aborts (SIGABRT, exit status 134) after printing

```text
thread '<unknown>' has overflowed its stack
fatal runtime error: stack overflow, aborting
```

## Measurements

Debug build, one literal of N `\\`, largest N that compiled and smallest that aborted:

| Stack | Compiled | Aborted |
|---|---|---|
| 1 MiB | 1,216 | 1,280 |
| 2 MiB | 2,432 | 2,560 |
| 8 MiB | 9,728 | 10,240 |
| 64 MiB | 81,920 | 86,016 |

About 820 bytes of stack for each escape. It is per literal: 100,000 escapes spread over 1,000 strings compile on 2 MiB, and a literal of 131,072 characters with no escape compiles. The same numbers hold for `\"`, for `\.` and `\x41` in a regex, for a meta string, a string in a condition and a triple-quoted string.

The two other inputs, on 2 MiB:

| Input | Compiled | Aborted |
|---|---|---|
| a block comment of N lines that each start ` * ` | 2,176 | 2,304 |
| N U+00A0 in a row, where a space may be | 2,432 | 2,560 |

With `yara-x`, `yara-x-parser` and `logos` at `opt-level = 3` and the rest of the build unoptimized (`cargo build --config profile.dev.package.yara-x.opt-level=3 --config profile.dev.package.yara-x-parser.opt-level=3 --config profile.dev.package.logos.opt-level=3`), none of them overflow: 1,048,576 of each compile on a 1 MiB stack.

## Likely cause

The tokenizer's patterns for these tokens have a repeated group with more than one branch, for example the string literal in `parser/src/tokenizer/mod.rs`:

```text
"( \\. | [^"\n\\] )*"
```

The state machine logos generates for it seems to call a function for each pass through the `\\.` branch, and for each multi-byte space, and without tail-call optimization each call keeps its frame. The block comment's `([^/*][^*]*\*+)*` and the whitespace pattern's multi-byte alternatives behave the same way.

## Suggested direction

Match these tokens with a callback that loops over `lexer.remainder()` and bumps, instead of a regex with a repeated alternation; or cap the length of a literal in the tokenizer and return an error past it. Either makes the stack use independent of the input.

## Confirmed

Re-run on 2026-11-15 on yara-x 1.22.1 (the only version in the local cargo registry; no later release was fetched to check). Each case ran in a process of its own, on a thread of the stack size given, so an abort took nothing else down.

- Debug, 2 MiB: 2,432 escapes compiled and 2,560 aborted; the reproducer's 3,000 aborted with the compiler and with the parser alone; 2,176 comment runs compiled and 2,304 aborted; 2,432 U+00A0 compiled and 2,560 aborted.
- Optimized as above: the reproducer's 3,000 compiled on 2 MiB; 1,048,576 escapes, comment runs and U+00A0 each compiled on 1 MiB.

## How we found it

A service that turns a list of analyst-written values into YARA rules compiled a value of 4,096 backslashes in a test, and the test process aborted.
