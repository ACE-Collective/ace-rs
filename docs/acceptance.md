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
- The trees follow ace3 at checkpoints, not at every commit (`PLAN.md` decision 14). Between checkpoints the trees, the dumps and the module inventory stay at the commit `tools/ace3/trees/reference/index.json` names, and `tools/ace3/modules/check` checks the inventory there and says how far ace3's checkout has moved past it. `make-trees` and `make-dumps` run ace3's code as it stands, so they are run at a checkpoint only, on the whole set, so that no reference mixes commits. At a checkpoint, port or list whatever moved.
- A row that covers only samples under `local/` has to name them, because CI doesn't have them and would call a `*` row stale.

## What enforces it

`tests/e2e/run` runs `ace compare --threshold`, which exits non-zero and names each cause on any of:

- an unexplained difference, in any sample;
- a row of `differences.md` that matched nothing;
- a sample that couldn't be read, submitted or finished in time;
- a sample absent from this machine, unless `CI` is set.

`tests/e2e/run --compare` reports without enforcing, for working through a port's differences. `report.md` and `report.json` under `target/e2e/compare/` have every difference, and `report.md` says whether the threshold is met.

## How the samples run

`ace compare` keeps several samples in the stack at a time (`--jobs`, 8 unless it says). `tests/e2e/run` gives its stack's parser and sandbox pools 4 to 8 slots by the machine's CPUs and passes that many, and `tests/e2e/run --jobs 1` runs the samples one at a time, as every run did before 2026-11-16. Either way each sample goes through the whole stack and is diffed with ace3's tree, and the threshold is the same. A sample's tree doesn't depend on what runs beside it: `crates/ace-app/src/compare.rs` (*Several samples at once*) says why, and `docs/measurements/compare-speed.md` has the runs that checked it.

Two runs of the same code don't give the same report byte for byte, one at a time or not. Three things move, all in rows already listed:

- Ghostscript's rewrite of a PDF has a new sha256 each run, so the `md5:`, `sha1:` and `sha256:` observables of its hashes do too. Their number doesn't change.
- pdftotext's text of a PDF and of its rewrite is one observable, redirected to whichever of the two PDFs has the lower sha256, so about half of those redirections differ from ace3's on any run. The count of explained differences moves by a few for this reason alone (38 and 41 of them in two runs of one commit).
- Values that hold a time or a task's temporary directory: exif's file dates, `dmg_analyzer`'s stderr, `de4dot`'s stdout.

So a count of explained differences that moves by a few between runs is not a regression by itself. A difference with no row is one, on any run.

## A port of a library

A Rust port of a library is compared with the library itself before its module moves (`PLAN.md` 4.9 to 4.12). `tools/library-diff/run LIBRARY --right rust:PACKAGE/BIN` runs each side on every file in `samples/manifest.json`, whatever its kind, and has the same threshold: a difference that `tools/library-diff/differences/LIBRARY.md` doesn't list fails, and so does a row that matches nothing. Rows follow *Listing a difference*. The top of that script has the contract. `tools/library-diff/run --all` runs each library on both sides, about 19 minutes over 364 samples, and `tests/e2e/run` runs only its `self-test`.

## Samples CI doesn't have

`samples/local/` is git-ignored, so `ace compare` reports those samples as absent in CI. When the `CI` variable is set, `tests/e2e/run` passes `--allow-absent`, and the threshold holds over the tracked samples only. The report names each absent sample and says the threshold says nothing about them.

So CI catches a regression on the tracked samples, and can't accept a port by itself. Everywhere else an absent sample fails the run, so a passing run on a developer's machine covers the whole set. Accepting a port takes a passing run with `samples/local/` in place (`tools/samples/gather` makes them), and that run's numbers in the step's commit.
