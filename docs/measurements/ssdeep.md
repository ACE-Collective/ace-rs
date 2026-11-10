# fuzzyhash against ssdeep

PLAN.md 7.3 chose the `fuzzyhash` crate for ace3's `ssdeep` module, to be checked in 7.5 batch 2 against ssdeep's hashes and its `-m` scores, and said the module goes to the sandbox runner if they differ. They differ, so `ssdeep` waits for batch 10 (`docs/modules.md`).

Measured on 2026-11-09. ssdeep 2.14.1 is ace3's, in `ace-dev-1`; fuzzyhash 0.2.2 ran in ace4's dev container.

## The files

`tools/ace3/ssdeep/gen.py`, seeded, writes 420 files: 60 base files of 1,024 to 2,048,000 bytes, random, text, a short random run repeated, or zeros, and six edited copies of each, with bytes changed, inserted and deleted, some cut short and some with another file's bytes added. The module hashes files of 1 KB to 2,048,000 bytes.

## Commands

In `ace-dev-1`, in the directory of the files:

    ssdeep -s base* > ../hashes_base
    ssdeep -s -b * > ../all_hashes
    for f in *; do ssdeep -s -m ../hashes_base $f; done > ../matches

In ace4's dev container, `tools/ace3/ssdeep/compare.rs` as a binary crate depending on `fuzzyhash = "0.2.2"`, built with `--release`: each file's `FuzzyHash::new(data)` after `finalize()`, then `FuzzyHash::compare` of each file's hash with each base file's, printed as `ssdeep -m` prints a match, a score above 0. `compare` returns an error, `NoCommonSubstrings`, where ssdeep scores 0; that counts as 0. One run each: both are deterministic.

## Results

- Hashes: the same for all 420 files.
- `-m` scores: ssdeep prints 305 matches. fuzzyhash gives 304 of them the same score, gives one 71 where ssdeep gives 69 (`var055_5` against `base055_rand`), and finds 31 matches of 100 that ssdeep doesn't find at all, all of them between the edited copies of a repeated file and that file.

The reason is in fuzzyhash's `compare.rs`. Before comparing, ssdeep 2.14.1 shortens each run of more than three identical characters in a hash to three (`eliminate_sequences`). fuzzyhash's version of that function compares each character with `input[j]`, the last one it kept, where ssdeep compares the current one, so it drops characters that aren't in a run. A repeated file's hash is mostly one character, such as `8EEEE...E4` and `8EEEE...ED`: ssdeep keeps `8EEE4` and `8EEED`, which share no seven characters, so it scores 0; fuzzyhash drops the last character of each and keeps `8EEE` twice, and returns 100 by its shortcut for equal strings. `var055_5`'s hash has a run of 34 `B`s, and the same function changes its score.

So ace4 can't run the module on fuzzyhash and give ace3's matches, and the module tags a match `ssdeep` and sandboxes the file, which a wrong 100 would do. Fixing the crate would be a fork of an unmaintained crate (last release 2023); ssdeep 0.7.0, the crate over libfuzzy, is GPL-3. Batch 2 sent the module to the runner, with ssdeep 2.14.1 in the sandbox pool's image; batch 10 ported the comparison instead, below, so the module stays a crate, as PLAN.md 7.3 decided.

## Batch 10: the comparison ported

7.5's batch 10 kept fuzzyhash's hash and wrote ssdeep 2.14.1's comparison, `fuzzy_compare` (`crates/ace-mod-files/src/ssdeep.rs`): runs cut to three as ssdeep's `copy_eliminate_sequences` cuts them, ssdeep's rolling hash and its check for a common run of 7, the edit distance with a change costing 2, the identical-hashes 100 only when both strings match, and the cap on a small block size's score only below a block size of 45, where fuzzyhash caps every score. The module runs in the parser pool, with no tool.

Measured on 2026-11-10, once (both deterministic). In `ace-dev-1`, the files `gen.py` writes and ssdeep's answers, as above (`ssdeep -s base*`, `ssdeep -s -b *`, and `ssdeep -s -m hashes_base` of each file); in ace4's dev container, `ACE4_SSDEEP_DIR=<dir> cargo test -p ace-mod-files --lib ssdeep -- --ignored` (`hashes_and_scores_are_ssdeeps`), which hashes each file and scores it against each base hash, printing what `ssdeep -m` prints for a score above 0.

- Hashes: the same for all 420 files.
- Scores: the same 305 matches with the same scores, the 69 of `var055_5` against `base055_rand` and the 0s of the repeated files' copies included.

The reference dumps (`make-dumps ssdeep`, `tools/ace3/dumps/fixtures/ssdeep`) run ace3's module on seven files against three known hashes, at its threshold of 90 and at 1; the module matches all 14 (`crates/ace-mod-files/tests/reference.rs`), the repeated file's edited copy, which fuzzyhash's comparison scored 100, among them.
