# 0001: Keep Rust for the core

Status: accepted (PLAN.md 1.32), reopened on 2026-11-03 (PLAN.md 2.33; see *Reopened* below).

## The question

DESIGN.md picks Rust because a model writes every change and the compiler checks each one before a person reads it. It names two results that could change that pick: Rust's build loop, and how ACE's signatures repo fares on yara-x under the ported scanner layer. Phase 1 measured both. The alternative is DESIGN.md's *Go for the core*: Go builds in seconds and has River as a proven Postgres queue, but its compiler checks less.

## What phase 1 found

### YARA on yara-x (1.11 and 1.12)

[yara-compare.md](../measurements/yara-compare.md) has the details. ace3's scanner (yara-python 4.5.4 under yara_scanner_v2 3.0.0) and ace4's port on yara-x 1.22.1 differed nowhere:

- **Compiling.** All 97 rule files in the signatures repo at commit 0ca119e compile the same way in both. One file fails in both, because it uses `vt.net`, a field only VirusTotal Livehunt has. The 87 files ace3's yara service loads give 288 rules in both, with identical meta.
- **Matching on the sample set.** 52 units from 0.8's 53 samples gave 3 raw matches from 3 rules, all dropped by the meta filter in both scanners. That's 0 differences, but it exercises almost nothing.
- **Matching on the rule files themselves.** Scanning each rule file as a unit, with and without tags, gave 316 matches from 91 rules, identical in every offset, identifier and length. The filter agreed on all 316.
- **Mime types.** libmagic in ace4 agrees with ace3's `file` on 53 of 53 samples.
- **Incompatibilities to record:** none. One rule uses `pe.number_of_signatures`, which yara-x marks deprecated.

What this doesn't cover:
- The SVS corpus. It lives in production, so the match half ran on local files only.
- Conditions that use YARA modules or file formats. The rule-file units exercise strings and the filter, not the pe module, magic or file sizes.

yara-x also compiled the bv namespace in 0.42 s against libyara's 0.03 s, in one release-build run. A ruleset is built once per commit (1.6), so that cost lands once per signature change, not per scan.

### The build loop (1.31)

[build-loop.md](../measurements/build-loop.md) has the method and raw data. These are medians of five runs in the dev container on this laptop (Rancher Desktop, arm64, 8 CPUs), with mold and sccache. Each run is `cargo test --workspace --no-run`.

| Series | Spike, ace4's profile | Workspace at the end of phase 1 |
|---|---|---|
| Clean build, empty cache | 52.5 s (50.0 to 56.6) | 44.0 s (39.4 to 46.5) |
| Clean build, cache kept | 9.2 s (8.8 to 11.7) | 15.7 s (15.4 to 17.0) |
| No-op | 0.1 s | 0.2 s |
| One-line edit in a leaf crate, to a runnable test binary | 0.5 s | 1.1 s (0.9 to 1.4) |
| One-line edit in `ace-results`, which 7 crates depend on | | 2.8 s (2.5 to 2.9) |

The edit series measure what an agent waits for while fixing compile errors: 1 to 3 seconds per attempt. DESIGN.md expected minutes for a clean build. It's under a minute, and with the cache kept, about 16 seconds.

What else these numbers include:
- ace3's idle stack was running on the same VM.
- Every run exited 0 and compiled the expected number of crates.
- The workspace doesn't use axum, sqlx, askama or the AWS SDK yet. The spike does, so those crates will add to the workspace's clean build when phase 2 brings them in. How much they add to an edit in the core is what the measurement at the end of phase 2 checks.
- CI's Linux runner hasn't been measured, because ace4 has no remote yet.

One cost showed up that DESIGN.md didn't name: disk. With full debug info, each test binary that links yara-x was 389 MB. Stale copies filled the Docker VM's 98 GB disk, which ace3 shares, once, and brought it to 1.8 GB free a second time. Building dependencies without debug info brought the largest test binary to 105 MB and a full test build's `target/` to 3.1 GB. The disk still needs watching while both stacks run on one laptop.

### What wasn't compared

Nothing was built in Go, so this record has no Go numbers. DESIGN.md says Go builds in seconds. Rust's edit loop here is also seconds. Go would win clean builds, but clean builds are rare with sccache and `target/` on a named volume.

## Decision

Keep Rust for the core and the modules. Neither result that could have changed the pick did. yara-x is compatible with every rule in the signatures repo that the comparison could check, and an edit costs an agent 1 to 3 seconds.

## What would reopen it

- **A slow core edit.** The build loop is measured again at the end of phase 2 (PLAN.md 2.33), with sqlx, axum and the AWS SDK in the workspace. A one-line edit in `ace-core` taking more than 10 seconds to a runnable test binary reopens this record.
- **A broken rule.** The SVS corpus comparison, once ace4 goes past a proof of concept, finds a rule that yara-x matches differently and that can't be fixed in the port or the rule.

## Sign-off

Signed off by Matthew Wilson on 2026-11-02.

## Reopened: 2026-11-03

PLAN.md 2.33 measured the build loop again at the end of phase 2, with sqlx, axum and the AWS SDK in the workspace. [build-loop.md](../measurements/build-loop.md) has the method and raw data. A one-line edit in `ace-core` took 12.3 seconds to runnable test binaries, the median of five runs, with a range of 11.7 to 13.3. That is over this record's 10-second limit in every run, so the decision is reopened. The decision above stands as written until it is decided again.

| Series | 1.31 | 2.33 |
|---|---|---|
| Clean build, empty cache | 44.0 s (39.4 to 46.5) | 79.3 s (76.1 to 94.9) |
| Clean build, cache kept | 15.7 s (15.4 to 17.0) | 34.6 s (33.0 to 43.5) |
| No-op | 0.2 s | 0.2 s |
| One-line edit in `ace-mod-yara` | 1.1 s (0.9 to 1.4) | 14.6 s (12.6 to 16.0) |
| One-line edit in `ace-results` | 2.8 s (2.5 to 2.9) | 15.7 s (14.4 to 16.9) |
| One-line edit in `ace-core` | | 12.3 s (11.7 to 13.3) |

What bounds the result:
- ace3's stack ran on the same VM throughout, mostly idle (median 16% to 28% of one CPU per series), with bursts up to 3.3 CPUs from tests in ace3's dev container. The edit-core series saw bursts up to 1.2 CPUs.
- Every run exited 0 and compiled the expected crates: 5 for the `ace-core` edit.
- One run with `--timings` put `ace-core`'s own compile at 0.75 seconds. Most of the time went to the 44 test executables of `ace-core`, `ace-pool`, `ace-app`, `ace` and `ace-site-example`, each recompiled and linked against sqlx, axum, the AWS SDK and yara-x, at 1.5 to 2.9 seconds each, run in parallel on 8 CPUs. Fewer test executables per crate is the change that measurement points to. It hasn't been tried, and nothing has been built in Go.
