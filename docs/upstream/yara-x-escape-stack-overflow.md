# Draft bug report for yara-x: stack overflows in the lexer and the parser

**Status: a draft. Not submitted anywhere, and nobody has been contacted.** The owner decides whether and where to send it. `docs/measurements/yara-guard.md` has every measurement behind it, and `crates/ace-yara/src/guard.rs` is how ace4 protects itself meanwhile.

---

## Title

Stack overflow (process abort) when compiling or parsing a rule with many escapes in one literal, or with deep nesting

## Versions

- yara-x 1.22.1 and yara-x-parser 1.22.1, with logos 0.16.1, from crates.io.
- rustc 1.99.1, on Linux 6.18, aarch64.
- Not checked against a later release or against `main`.

## Summary

Three inputs make `yara_x::Compiler::add_source` and `yara_x_parser::Parser` overflow the thread's stack. Rust can't catch that, so the process aborts with SIGABRT. Any program that compiles rules it didn't write, such as a service that builds a ruleset from a shared repository, can be taken down by one rule file.

1. **Many escape sequences in one literal** (debug builds). A text string, a meta string, a string in a condition, a regex or a triple-quoted string holding about 2,500 escapes (`\\`, `\"`, `\.`, `\x41`) overflows a 2 MiB stack. So does a block comment with about 2,300 runs of `*`, and about 2,500 U+00A0 in a row. These go away when `yara-x-parser` and `logos` are optimized.
2. **Deep nesting** (every build measured). 384 nested parentheses overflow a 2 MiB stack, 200 `not` in a row, 144 nested `for` loops, or 96 nested `pe.sections[...]`. Optimizing doesn't change the first of these.
3. Not an overflow, but found alongside: **nested calls take three times as long for each level**, and a rule past `MAX_AST_DEPTH` is dropped with no error.

## Reproducer 1: escapes in one literal

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
thread '<unknown>' (48786) has overflowed its stack
fatal runtime error: stack overflow, aborting
```

Measured threshold by stack size, debug build, one literal of N `\\`:

| Stack | Largest N that compiled | Smallest N that aborted |
|---|---|---|
| 1 MiB | 1,216 | 1,280 |
| 2 MiB | 2,432 | 2,560 |
| 8 MiB | 9,728 | 10,240 |
| 64 MiB | 81,920 | 86,016 |

About 820 bytes of stack for each escape. It is per literal: 100,000 escapes spread over 1,000 strings compile on 2 MiB. A literal with no escape of 131,072 characters compiles. The same numbers hold for `\"`, for `\.` and `\x41` in a regex, and for a triple-quoted string. A block comment of N lines that each start ` * ` aborts at 2,304 on 2 MiB (2,176 pass), and N U+00A0 where a space may be at 2,560 (2,432 pass).

With `yara-x`, `yara-x-parser` and `logos` built at `opt-level = 3` (the rest of the build unoptimized), none of these overflow: 1,048,576 escapes in one literal compile on a 1 MiB stack. So this affects debug builds, test suites among them, and any build where those crates aren't optimized.

**Likely cause.** The tokenizer's patterns for these tokens have a repeated group with more than one branch, for example the string literal in `parser/src/tokenizer/mod.rs`:

```text
"( \\. | [^"\n\\] )*"
```

The state machine logos generates for it seems to call a function for each pass through the `\\.` branch and for each multi-byte space, and without tail-call optimization each call keeps its frame. The block comment's `([^/*][^*]*\*+)*` and the whitespace pattern's multi-byte alternatives behave the same way.

**Suggested direction.** Match these tokens with a callback that loops over `lexer.remainder()` and bumps, instead of a regex with a repeated alternation, or cap the length of a literal in the tokenizer and return an error past it. Either makes the stack use independent of the input.

## Reproducer 2: deep nesting

```rust
fn main() {
    let n = 400;
    let source = format!(
        "rule r {{ condition: {}true{} }}",
        "(".repeat(n),
        ")".repeat(n)
    );
    std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            let mut compiler = yara_x::Compiler::new();
            let _ = compiler.add_source(source.as_bytes());
        })
        .unwrap()
        .join()
        .unwrap();
}
```

**Expected:** an error such as "expression nested too deeply", or the rule compiles.

**Actual:** stack overflow, and the process aborts.

Measured on a debug build, largest N that returned / smallest that aborted:

| N of | 1 MiB | 2 MiB | 8 MiB |
|---|---|---|---|
| nested `(` ... `)` | 184 / 192 | 368 / 384 | 9,728 (no rule past 1,499, see below) / 10,240 |
| `not` in a row (`-` and `~` are the same) | 92 / 96 | 192 / 200 | 768 / 800 |
| nested `for any i in (1..2) : (` | 68 / 72 | 136 / 144 | 9,728 (no rule) / 10,240 |
| nested `(true and ` | 76 / 80 | 160 / 168 | 640 / 672 |
| nested `pe.sections[` | 44 / 46 | 92 / 96 | 384 / 400 |
| nested `( 06 | ` in a hex pattern | 416 / 432 | 832 / 864 | 15,360 / 15,872 |
| `(` that never close (a syntax error) | 1,152 / 1,216 | 2,304 / 2,432 | 9,728 / 10,240 |

With `yara-x`, `yara-x-parser` and `logos` at `opt-level = 3`: nested parentheses still 368 / 384 on 2 MiB, `not` 1,472 / 1,536, `pe.sections[` 224 / 232.

**Likely cause.** `ParserImpl` is recursive descent with no depth check. `MAX_AST_DEPTH` (3,000, `parser/src/ast/cst2ast.rs`) is checked when the AST is built from the parser's events, after the parser has recursed, and is itself more than a 2 MiB stack holds: the compiler's own recursion over the AST dies at 96 nested indexes.

**Suggested direction.** Count depth in the parser itself (where `begin` and `end` bracket a production) and report an error past a limit that fits the default thread stack with the compiler's recursion in mind. A few hundred levels is far more than rules use. Alternatively grow the stack on demand with something like the `stacker` crate around the recursive functions of the parser and the compiler.

## Also found

**A rule past `MAX_AST_DEPTH` is dropped with no error.** On a 64 MiB stack, a rule with 1,490 nested parentheses compiles, and with 1,500 `add_source` returns `Ok` and the compiled rules hold no rule. 2,990 `not` compile; 3,010 give no rule. Expected: an error, so the caller knows the rule isn't there.

**Nested calls cost three times as much for each level.** `math.abs(math.abs(...1...))`, debug build: 8 levels 195 ms, 10 levels 1.85 s, 12 levels 17.5 s, 13 levels 54.4 s. Optimized as above: 10 levels 166 ms, 12 levels 1.35 s, 14 levels 11.4 s and then `error[E001]: syntax error`. `uint32(uint32(...))` is the same, and so is the parser with no compiler. The parser's alternatives (`begin_alt` and `alt` in `parser/src/parser/mod.rs`) seem to parse a call's arguments again for each alternative that fails after them, so each level multiplies the work. Deciding the alternative from the next tokens before descending, or remembering a failed production at a position, would make it linear.

## How we found it

A service that turns a list of analyst-written values into YARA rules compiled a value of 4,096 backslashes in a test and the test process aborted. The other cases came from bisecting crafted rules, each in a process of its own, on threads of fixed stack sizes.
