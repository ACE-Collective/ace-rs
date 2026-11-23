# Draft bug report for yara-x: each level of nested calls triples the parser's time

**Status: a draft. Not submitted anywhere, and nobody has been contacted.** The owner decides whether and where to send it. It is one of four reports that were first drafted as one: `yara-x-lexer-stack-overflow.md`, `yara-x-nesting-stack-overflow.md`, `yara-x-rule-dropped-past-depth-limit.md` and this one. `docs/measurements/yara-guard.md` has every measurement, and `crates/ace-yara/src/guard.rs` is how ace-rs protects itself meanwhile.

---

## Title

Parsing a call nested N levels deep takes time proportional to 3^N

## Versions

- yara-x 1.22.1 and yara-x-parser 1.22.1, with logos 0.16.1, from crates.io.
- rustc 1.99.1, on Linux 6.18, aarch64.
- Not checked against a later release or against `main`.

## Summary

A condition that nests a function call inside its own argument, such as `math.abs(math.abs(math.abs(1)))`, takes about three times as long to parse for each level. Twelve levels take over a second in an optimized build and 17 seconds in a debug build; at that rate twenty would take hours, and days in a debug build. The rule is short and valid, and nothing overflows: the process spends the time in the parser. A program that compiles rules it didn't write can be held for as long as an author likes by one line.

## Reproducer

```rust
// Cargo.toml: yara-x = "=1.22.1"
fn main() {
    let n = 12;
    let source = format!(
        "import \"math\" rule r {{ condition: {}1{} == 1 }}",
        "math.abs(".repeat(n),
        ")".repeat(n)
    );
    let started = std::time::Instant::now();
    let mut compiler = yara_x::Compiler::new();
    compiler.add_source(source.as_bytes()).unwrap();
    println!("{n} levels: {:?}", started.elapsed());
}
```

**Expected:** time linear in the length of the rule: milliseconds.

**Actual:** the rule compiles, after a time that triples with each level.

## Measurements

`math.abs(math.abs(...1...))`, one rule, one run each:

| Levels | Debug | `yara-x`, `yara-x-parser`, `logos` at `opt-level = 3` |
|---|---|---|
| 6 | 33 ms | |
| 8 | 176 ms | 33 ms |
| 10 | 1.73 s | 148 ms |
| 12 | 16.9 s | 1.33 s |
| 13 | 54.4 s † | 4.08 s |
| 14 | over 60 s † | 11.4 s, and then a syntax error † |

† From `docs/measurements/yara-guard.md`, measured the same day and not run again. A compile of nothing takes about 15 ms, which the short times include.

Two levels cost 9.8 times as much (176 ms to 1.73 s to 16.9 s), so one costs about 3.1 times. `uint32(uint32(...))` costs the same (12 levels, 14.4 s in a debug build), and so does the parser with no compiler (12 levels, 34.6 s for two parses). The cost is per expression: 1,000 expressions of six levels took 20.2 s in a debug build, and 100 of eight levels 19.1 s.

## Likely cause

The parser tries its alternatives in turn (`begin_alt` and `alt` in `parser/src/parser/mod.rs`) and backtracks when one fails. A call's arguments seem to be parsed again for each alternative that fails after them, about three times at each level, so each level multiplies the work of the levels inside it.

## Suggested direction

Decide the alternative from the next tokens before descending, so a primary expression that starts with an identifier and `(` is parsed as a call once; or remember that a production failed or succeeded at a position (packrat memoization) so it isn't parsed again. Either makes the time linear. A limit on the depth of nested calls would bound it without fixing it.

## Confirmed

Re-run on 2026-11-15 on yara-x 1.22.1 (the only version in the local cargo registry; no later release was fetched to check), each case in a process of its own on an 8 MiB thread.

- Debug: 6, 8, 10 and 12 levels, the times in the table.
- Optimized as the table's heading says: 8, 10, 12 and 13 levels, the times in the table.
