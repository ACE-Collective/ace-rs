# file_type's JavaScript check: oxc against node

ace3's `file_type` gives a file `type=script.javascript` when its mime type or extension says JavaScript, `node --check` passes on it, and grep finds a keyword, an arrow, a `.then(` or a call (`is_javascript_file` in `saq/modules/file_analysis/is_file_type.py`). PLAN.md 7.3 replaced node with oxc_parser 0.157.0 and asked batch 2 to measure where V8 and oxc disagree. `crates/ace-mod-files/src/javascript.rs` is the check.

Measured on 2026-11-09: node v24.22.2 (V8 13.6) in `ace-dev-1`, oxc in ace-rs's dev container.

## Cases

`crates/ace-mod-files/tests/data/js_oracle.py`, run in `ace-dev-1` with `/venv/bin/python3 -I js_oracle.py js_cases.json`, writes each case as `case<n>.js` and records `node --check`'s exit and ace3's own `is_javascript_file` on it. 850 cases: 245 hand-written (scripts and modules, top-level `return` and `await`, strict-mode and early errors, regular expression syntax and flags, templates, classes and private names, destructuring, `using`, decorators, import attributes and phases, TypeScript and JSX, Annex B HTML comments, odd whitespace and escapes, empty and broken files) and 600 seeded mutations of five ordinary files (tokens inserted, deleted and replaced). `javascript::oracle` in the crate's unit tests compares each case and fails on any disagreement not listed.

How node checks a `.js` file: as CommonJS, wrapped in a function, so `return` and `new.target` are allowed at the top; when that fails on module syntax, node 24 checks it as an ES module, so `import`, `export` and top-level `await` pass too. A name ending in `.JS` or another case isn't linked by ace3 and node refuses its extension, so it fails. ace-rs parses with oxc as CommonJS, then as a module, with oxc's semantic pass for V8's early errors (a redeclared `let`, a duplicate private name and the like).

## Results

- First run: 5 of 850 disagreed, all proposals oxc parses and V8 13.6 doesn't ship: a class decorator, a method decorator, an `accessor` field, import attributes written `assert { ... }` (V8 dropped `assert`), and `import defer`. The check now fails a file using any of them (`Unshipped` in `javascript.rs`). `import source`, which V8 has, passes.
- Now: 0 of 850 disagree. Where node's answer and ace-rs's agree, `is_javascript_file` agrees too: the grep pattern runs on Rust's `regex` line by line.

## Nesting and the task's stack

V8 under node's default stack refuses deep nesting. Measured with `node --check` on `n` nested levels, binary search, one run each: parentheses pass up to 1,950, arrays 2,837, blocks 1,842, object literals 1,560, functions 1,686. ace-rs fails a file whose brackets nest deeper than 1,560 (`MAX_NESTING`), counted outside strings, comments and template text, so a file V8 accepts at 1,561 to 2,837 levels of some constructs fails in ace-rs.

oxc has no recursion limit, and a stack overflow kills a contained task, which would leave the file with no file_type result and keep every module that depends on it off the file. So oxc runs on a stack of its own (`stacker`), sized from a count of every byte and word that could open a nested level, in strings or not, at 1.5 KiB each, over 16 MiB. The costliest construct measured is `x=>`: `probe_depth` (an ignored unit test, `ACE_RS_JS_DEPTH` and `ACE_RS_JS_KIND`) parses each prefix repeated on an 8 MiB stack, in a dev build with oxc at `opt-level = 3`, binary search: `x=>` up to 7,568 levels (about 1.1 KiB a level), `(` 10,376, `[` 11,108, `a=` and `a?b:` 14,404, `{` 16,113, `if(1)` 24,901, `new ` 30,761, `a**` 32,226, `!` and `typeof ` 65,429, `-` 207,031. A file whose count passes 1 GiB of stack (`MAX_STACK`), about 690,000 counted bytes, fails the check: a large JavaScript file, several MB of minified code, isn't marked `type=script.javascript` where ace3 marks it. The task's limit is 2 GiB of address space for this.

The hostile unit test `deep_chains_without_brackets_parse_on_their_own_stack` parses 100,000 nested arrows, 400,000 `!`, 100,000 assignments and 100,000 nested `if`s on a test thread's 2 MiB: 22 to 43 ms each, one run. V8 runs out of stack on each of these and node fails them; ace-rs passes them, a second known disagreement, only for files built to nest without brackets.
