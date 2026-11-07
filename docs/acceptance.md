# Accepting a port

A module port is accepted when `tests/e2e/run` passes on a machine that has the whole sample set. From phase 3 on this is what "3.3's comparison accepts it" means in `PLAN.md`.

## The threshold

**No unexplained difference over the whole sample set.**

Each sample in `samples/manifest.json` runs through ace4 with `ace compare`, and its tree is diffed with ace3's in `tools/ace3/trees/reference/`. Each difference gets the class of the first row of `tools/ace3/trees/differences.md` that matches it.

| Class | Row | For acceptance |
|---|---|---|
| unexplained | none | Blocks it. Zero are allowed. |
| explained | under any other heading | Allowed. The systems differ on purpose, or the difference is known and harmless. |
| unported | under *Effects of modules not ported* | Allowed. What a module ace4 doesn't have added outside its result. A row here only matches what ace3 has and ace4 lacks, and it's the next port's to remove. |
| harness | under *Harness limits* | Allowed. The two runs saw different worlds, so it says nothing about the port. A row's condition has to tell that from a real failure, as `ace3 holds nothing recorded` does. |

`(tree)` differences count like any module's. An observable, path, tag or relationship only one side has is a real disagreement, even when no module's result differs.

A module ace4 doesn't have is skipped: its results come out of both trees and the report counts them. A port is compared from when it's registered.

## Listing a difference

A row says a difference is fine, so it needs a reason someone verified: read ace3's code and ace4's, look at the two values, and write down why they differ and why that's right. Don't list a difference because it's the last one left, or because the cause sounds likely. Fix what's a bug.

- Keep a row as narrow as what was verified: the sample, the path and a condition if the values can tell a real failure apart.
- A row that matches nothing fails the threshold, so the list can't go stale. Rows that only cover samples this run didn't compare are left out of that check.
- `ace3`'s newest commit is what the trees follow (`PLAN.md` decision 14). After `tools/ace3/trees/make-trees`, port or list whatever moved.
- A row that covers only samples under `local/` has to name them, because CI doesn't have them and would call a `*` row stale.

## What enforces it

`tests/e2e/run` runs `ace compare --threshold`, which exits non-zero and names each cause on any of:

- an unexplained difference, in any sample;
- a row of `differences.md` that matched nothing;
- a sample that couldn't be read, submitted or finished in time;
- a sample absent from this machine, unless `CI` is set.

`tests/e2e/run --compare` reports without enforcing, for working through a port's differences. `report.md` and `report.json` under `target/e2e/compare/` have every difference, and `report.md` says whether the threshold is met.

## A port of a library

A Rust port of a library is compared with the library itself before its module moves (`PLAN.md` 4.9 to 4.12). `tools/library-diff/run LIBRARY --right rust:PACKAGE/BIN` runs each side on every file in `samples/manifest.json`, whatever its kind, and has the same threshold: a difference that `tools/library-diff/differences/LIBRARY.md` doesn't list fails, and so does a row that matches nothing. Rows follow *Listing a difference*. The top of that script has the contract. `tools/library-diff/run --all` runs each library on both sides, about 4.5 minutes, and `tests/e2e/run` runs only its `self-test`.

## Samples CI doesn't have

`samples/local/` is git-ignored, so `ace compare` reports those samples as absent in CI. When the `CI` variable is set, `tests/e2e/run` passes `--allow-absent`, and the threshold holds over the tracked samples only. The report names each absent sample and says the threshold says nothing about them.

So CI catches a regression on the tracked samples, and can't accept a port by itself. Everywhere else an absent sample fails the run, so a passing run on a developer's machine covers the whole set. Accepting a port takes a passing run with `samples/local/` in place (`tools/samples/gather` makes them), and that run's numbers in the step's commit.
