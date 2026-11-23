# Draft bug report for yara-x: a rule past the depth limit is dropped and `add_source` returns `Ok`

**Status: a draft. Not submitted anywhere, and nobody has been contacted.** The owner decides whether and where to send it. It is one of four reports that were first drafted as one: `yara-x-lexer-stack-overflow.md`, `yara-x-nesting-stack-overflow.md`, this one and `yara-x-nested-call-parse-cost.md`. `docs/measurements/yara-guard.md` has every measurement, and `crates/ace-yara/src/guard.rs` is how ace-rs protects itself meanwhile.

---

## Title

`Compiler::add_source` returns `Ok` and compiles no rule when a rule nests past the AST depth limit

## Versions

- yara-x 1.22.1 and yara-x-parser 1.22.1, with logos 0.16.1, from crates.io.
- rustc 1.99.1, on Linux 6.18, aarch64.
- Not checked against a later release or against `main`.

## Summary

A rule that nests deeper than yara-x's own limit isn't compiled, and nothing says so: `add_source` returns `Ok(())`, the compiler holds no error, and the built `Rules` has no rule. A caller that checks `add_source`'s result, as the API asks, believes the rule is loaded, and it never matches.

On a small stack the same input overflows the stack first (`yara-x-nesting-stack-overflow.md`), so this shows where the stack is large enough: a process's main thread, a thread given more stack, or an optimized build.

## Reproducer

```rust
// Cargo.toml: yara-x = "=1.22.1"; cargo run --release
fn main() {
    let n = 1500;
    let source = format!(
        "rule r {{ condition: {}true{} }}",
        "(".repeat(n),
        ")".repeat(n)
    );
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let mut compiler = yara_x::Compiler::new();
            let added = compiler.add_source(source.as_bytes());
            let rules = compiler.build();
            println!("add_source: {:?}, rules: {}", added.map(|_| ()), rules.iter().count());
        })
        .unwrap()
        .join()
        .unwrap();
}
```

**Expected:** `add_source` returns an error that names the rule and the limit, as it does for any other rule it can't compile.

**Actual:**

```text
add_source: Ok(()), rules: 0
```

With `n = 1490` it prints `add_source: Ok(()), rules: 1`.

A second reproducer needs no larger stack, in an optimized build: 2,048 nested alternatives in a hex pattern, on a 2 MiB thread, return `Ok` and no rule.

```rust
let n = 2048;
let source = format!(
    "rule r {{ strings: $a = {{ 01 02 03 04 {}05{} }} condition: $a }}",
    "( 06 | ".repeat(n),
    " )".repeat(n)
);
```

## Measurements

| Input | Stack | Build | Compiles | Returns `Ok` with no rule |
|---|---|---|---|---|
| nested `(` ... `)` | 64 MiB | debug and optimized | 1,490 | 1,500 |
| `not` in a row | 64 MiB | debug and optimized | 2,990 | 3,010 |
| nested `(` ... `)` | 8 MiB | optimized | | 1,500 and 3,000 |
| nested `( 06 | ` in a hex pattern | 2 MiB | optimized | 128 | 1,536 to 5,120 |

"Optimized" is `yara-x`, `yara-x-parser` and `logos` at `opt-level = 3`. Between 256 and 1,280 levels the hex pattern is refused with `error[E014]: invalid regular expression`; from 1,536 it is dropped; at 6,144 the stack overflows. In a debug build on 8 MiB, nested parentheses and nested `for` loops return with no rule from 1,500 up to 9,728 levels (`docs/measurements/yara-guard.md`).

## Likely cause

`MAX_AST_DEPTH` (3,000, `parser/src/ast/cst2ast.rs`) stops the AST's construction, and what stops it isn't turned into a compile error: the rule's item is left out of the AST and the compiler has nothing to report. A parenthesized expression seems to cost two levels, which is why 1,500 parentheses reach a limit of 3,000 and 3,010 `not` do.

## Suggested direction

Report the limit as an error from `add_source` (and as an `Error` of `AST::errors()` for the parser's users), with the span of the expression that reached it. If the limit is kept as a guard against deep recursion, it also has to be reached before the parser has recursed that deep (`yara-x-nesting-stack-overflow.md`).

## Confirmed

Re-run on 2026-11-15 on yara-x 1.22.1 (the only version in the local cargo registry; no later release was fetched to check). Each case ran in a process of its own, on a thread of the stack size given.

- Every row of the table, in the builds it names: the debug rows on 64 MiB, and the optimized rows on 64, 8 and 2 MiB.
