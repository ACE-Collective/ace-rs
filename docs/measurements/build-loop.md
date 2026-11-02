# Build loop

PLAN.md step 0.5 times the build loop on a throwaway workspace that uses tokio, axum, sqlx, askama, the AWS S3 SDK and yara-x once each, before any ACE code exists. Step 1.31 repeats the measurements on the real workspace at the end of phase 1, and reruns the spike with the workspace's dev profile so the two compare like for like.

## Summary

Medians of five runs each, in seconds, in the dev container on macOS. Each column names the dev profile it used, and the profile matters: 0.5's spike built with Cargo's default dev profile (full debug info everywhere), and since commit 9e79bad the workspace builds dependencies without debug info and its own crates with line tables only. A link-bound number such as the edit loop isn't comparable across profiles, so the spike was measured again with the workspace's profile.

| Series | Spike, default profile (0.5) | Spike, ace4's profile (1.31) | Workspace, ace4's profile (1.31) |
|---|---|---|---|
| clean-cold | 59.2 | 52.5 | 44.0 |
| clean-warm | 11.3 | 9.2 | 15.7 |
| noop | 0.2 | 0.1 | 0.2 |
| edit in a leaf crate | 0.7 | 0.5 | 1.1 |
| edit in `ace-results`, which 7 crates depend on | | | 2.8 |

The sections below give each row's runs, ranges, sccache counts and what else the numbers include.

## What was measured

`tools/build-loop/make-spike` writes the spike: a Cargo workspace outside ace4's members with two crates. `spike-deps` uses the six libraries, and `spike-leaf` depends on it and holds one test that calls into all six, so its test binary links them. The build compiles 406 crates. The spike was deleted after the runs, and `make-spike` recreates it.

`tools/build-loop/measure` times one command in every run, `cargo test --workspace --no-run --frozen`, which ends with runnable test binaries. It runs four series of five runs:

- **clean-cold:** after `cargo clean`, with sccache's cache emptied first.
- **clean-warm:** after `cargo clean`, with sccache's cache kept from the run before.
- **noop:** with nothing changed since the last build.
- **edit:** after rewriting one line, `pub const EDIT_MARKER: u32 = N;`, in `spike-leaf/src/lib.rs`. Cargo recompiles `spike-leaf` and relinks its 614 MB test binary.

Versions: Rust 1.99.1, tokio 1.54.1, axum 0.8.9, sqlx 0.9.0 (postgres, macros, rustls on aws-lc-rs), askama 0.16.1, aws-sdk-s3 1.156.0 (default features, without aws-config) and yara-x 1.22.1 (default features). In 0.5 the dev profile is Cargo's default, with debuginfo and incremental compilation of workspace crates.

## Dev container on macOS (0.5)

Profile: Cargo's default dev profile, full debug info for every crate.

Measured on 2026-10-29 in the `dev` service from `compose.yaml`: Rancher Desktop's VZ virtual machine on Apple silicon (aarch64, Linux 6.18.37), 8 CPUs and 31.3 GB, linking with mold 2.37.1 through clang, sccache 0.18.0. The spike's source sat on the macOS bind mount and its `target/` on the `target` named volume. Raw data: [build-loop-0.5-dev-container.tsv](build-loop-0.5-dev-container.tsv).

| Series | Runs | Median (s) | Range (s) | Failed runs | Crates compiled | sccache hits / misses, each run |
|---|---|---|---|---|---|---|
| clean-cold | 5 | 59.2 | 58.2 to 61.1 | 0 | 406 | 0 / 862 |
| clean-warm | 5 | 11.3 | 10.4 to 11.9 | 0 | 406 | 862 / 0 |
| noop | 5 | 0.2 | 0.1 to 0.2 | 0 | 0 | 0 / 0 |
| edit | 5 | 0.7 | 0.7 to 0.7 | 0 | 1 | 0 / 0 |

One extra warm clean build, outside the series, broke sccache's statistics down. Its 862 cacheable compilations per clean build are 442 Rust crates, 275 C files and 145 assembly files. The C and assembly come from aws-lc-sys and ring, which the cc crate compiles through sccache because `RUSTC_WRAPPER` names it. Another 100 compilations per clean build can't be cached and run every time: 80 build scripts and proc-macro crates, 4 builds of the two workspace crates, which compile incrementally, and 16 that sccache files under other reasons (`-o`, `-` and `missing input`). Those, the build scripts' own work and linking are most of the 11.3 seconds a warm clean build still takes.

What else these numbers include:

- **ace3's stack on the same VM.** Its 27 containers were running throughout, idle: together about 16% of one CPU and 14 GiB of memory just before the runs.
- **No downloads.** `cargo fetch` ran first and isn't timed, and `--frozen` keeps every run offline. The registry sat on the `cargo-registry` volume.
- **Warm file caches.** The VM's page cache held the registry sources after the first run, so runs 2 to 5 of each series read less from disk than run 1. Run 1 of clean-cold is the slowest, by about 2 seconds.
- **sccache's own cost.** clean-cold includes writing every result to the cache. A build without sccache wasn't timed, so its cost alone isn't known.
- **No failures.** Every run exited 0, and the crates-compiled column shows each series did the work it names: all 406 crates for a clean build, none for a no-op, and only `spike-leaf` for an edit. A separate check after the series confirmed that an edit gives the test binary a new mtime and that it runs and passes.
- **The edit is the cheapest kind.** It changes a constant in a crate nothing else depends on. An edit in a crate that others depend on recompiles those too, and 1.31 measures that on real crates.

## Dev container on macOS (1.31)

Measured on 2026-11-02 on the same machine and container as 0.5: Rancher Desktop's VZ virtual machine on Apple silicon (aarch64, Linux 6.18.37), 8 CPUs and 31.3 GB, mold 2.37.1 through clang, sccache 0.18.0, Rust 1.99.1. ace3's 27 containers were running, idle, as in 0.5.

Profile, from ace4's `Cargo.toml` since commit 9e79bad: `[profile.dev] debug = "line-tables-only"` and `[profile.dev.package."*"] debug = false`. Each `runs.tsv` records the profile it measured on its `# profile:` line.

### The spike, with ace4's profile

`tools/build-loop/make-spike --ace4-profile` writes the same spike with those two sections added. The versions resolved as in 0.5 except aws-sdk-s3, which is now 1.157.0, a patch release on 1.156.0. Raw data: [build-loop-1.31-spike-ace4-profile.tsv](build-loop-1.31-spike-ace4-profile.tsv).

| Series | Runs | Median (s) | Range (s) | Failed runs | Crates compiled | sccache hits / misses, each run |
|---|---|---|---|---|---|---|
| clean-cold | 5 | 52.5 | 50.0 to 56.6 | 0 | 406 | 0 / 862 |
| clean-warm | 5 | 9.2 | 8.8 to 11.7 | 0 | 406 | 862 / 0 |
| noop | 5 | 0.1 | 0.1 to 0.2 | 0 | 0 | 0 / 0 |
| edit | 5 | 0.5 | 0.5 to 0.6 | 0 | 1 | 0 / 0 |

The leaf's test binary is 144 MB, against 614 MB with full debug info in 0.5. Less debug info to write and link is the likely cause: the edit loop, which only recompiles `spike-leaf` and relinks that binary, went from 0.7 to 0.5 seconds, and a warm clean build from 11.3 to 9.2.

### The real workspace

`tools/build-loop/measure` on `/workspace` at commit 1332770, the end of track C: the workspace's ten crates and their dependencies, 430 compiled crates in all, with yara-x 1.22.1, reqwest 0.13.5 on rustls and aws-lc-rs, tokio 1.54.1, jsonschema 0.60.2, schemars 1.2.3, mail-parser 1.0.1, icann-rdap-common 1.0.1, zip 9.2.2, sevenz-rust2 0.24.2 and unrar 0.5.8. The build ends with 32 test executables; the largest, `ace-mod-yara`'s reference test, is 119 MB. Raw data: [build-loop-1.31-workspace.tsv](build-loop-1.31-workspace.tsv).

Two edit series. `edit` rewrites a line added for the measurement to `crates/ace-mod-yara/src/lib.rs`, a leaf: nothing depends on it, but its three test binaries link yara-x. `edit-shared` is the edit series again, run straight after with `SERIES=edit`, on a line in `crates/ace-results/src/lib.rs`, which `ace-sdk`, `ace-testkit`, the four modules and `ace` depend on. Both lines were removed after the runs.

| Series | Runs | Median (s) | Range (s) | Failed runs | Crates compiled | sccache hits / misses, each run |
|---|---|---|---|---|---|---|
| clean-cold | 5 | 44.0 | 39.4 to 46.5 | 0 | 430 | 0 / 870 |
| clean-warm | 5 | 15.7 | 15.4 to 17.0 | 0 | 430 | 870 / 0 |
| noop | 5 | 0.2 | 0.2 to 0.3 | 0 | 0 | 0 / 0 |
| edit | 5 | 1.1 | 0.9 to 1.4 | 0 | 1 | 0 / 0 |
| edit-shared | 5 | 2.8 | 2.5 to 2.9 | 0 | 8 | 0 / 0 |

How the workspace differs from the spike:

- **Clean-cold is faster** (44.0 against 52.5): the workspace leaves out sqlx, axum and the AWS SDK, which the spike builds, and what it adds in their place compiles in less time.
- **Clean-warm is slower** (15.7 against 9.2): sccache can't cache 146 compilations per build here, against 100 in the spike, and the build links 32 test executables instead of one. The workspace crates themselves (40 compilations) build incrementally every time.
- **The leaf edit** recompiles one crate and relinks its three test binaries, up to 119 MB each, in 1.1 seconds.
- **The shared edit** recompiles the eight crates from `ace-results` down and relinks the test binaries of all of them, in 2.8 seconds.

**unrar's C++.** One extra cold build, outside the series, ran with `--timings` and a fresh sccache cache to break the work down. Its 870 cacheable compilations are 405 Rust crates, 320 C and C++ files and 145 assembly files; the spike's 275 C files and the 45 C++ files of unrar's vendored library make up the 320. unrar_sys's build script ran for 10.0 seconds, in parallel with the rest. The longest single unit was aws-lc-sys's build script at 38.4 seconds, which reqwest's rustls brings in, as sqlx's did for the spike. That build took 61.6 seconds in all, slower than any run of the clean-cold series, which suggests `--timings` or the cache's first fill adds time; it is one run, and only its breakdown is used here.

What else the 1.31 numbers include, as in 0.5:

- **ace3's stack on the same VM**, running and idle.
- **No downloads.** `cargo fetch` ran first and isn't timed, and `--frozen` keeps every run offline.
- **Warm file caches** after each series' first run.
- **sccache's own cost**, in clean-cold, which writes every result to the cache.
- **No failures.** Every run exited 0, and the crates-compiled column shows each series did the work it names: every crate for a clean build, none for a no-op, one crate for the leaf edit and eight for the shared one. After the series, `cargo test -p ace-mod-yara -p ace-results` in the same target directory ran the rebuilt test binaries: 36 tests passed.

## CI's Linux runner

Pending, as in 0.5. The `build-loop` workflow (`.github/workflows/build-loop.yml`) runs the same two scripts inside the dev image on GitHub's `ubuntu-24.04` runner, by hand from the Actions tab, and writes the same table to the run's summary. It hasn't run yet, because this checkout has no GitHub repository. As written it measures 0.5's spike, with Cargo's default profile; 1.31's rows on CI would need `make-spike --ace4-profile` and a run over the workspace as below.

## How to rerun

In the dev container. Each run gets its own target directory, and `measure` gives sccache its own cache directory, `$SCCACHE_DIR/build-loop`, so emptying it for the clean-cold series leaves the dev container's cache alone. Delete both when the numbers are recorded.

0.5's spike, with Cargo's default profile; add `--ace4-profile` after `make-spike` for 1.31's like-for-like run:

```sh
tools/build-loop/make-spike spike-build-loop
CARGO_TARGET_DIR=/workspace/target/build-loop-spike \
  tools/build-loop/measure spike-build-loop spike-build-loop/spike-leaf/src/lib.rs \
  /workspace/target/build-loop-results 5
rm -rf spike-build-loop /workspace/target/build-loop-spike /workspace/target/build-loop-results /sccache/build-loop
```

The workspace. `measure` edits a line `pub const EDIT_MARKER: u32 = N;`, which no crate has, so add one to the end of the leaf's and the shared crate's `lib.rs` first, and remove both afterwards:

```sh
for f in crates/ace-mod-yara/src/lib.rs crates/ace-results/src/lib.rs; do
  printf '\npub const EDIT_MARKER: u32 = 0;\n' >> "$f"
done
CARGO_TARGET_DIR=/workspace/target/build-loop-real \
  tools/build-loop/measure /workspace crates/ace-mod-yara/src/lib.rs \
  /workspace/target/build-loop-results-real 5
SERIES=edit CARGO_TARGET_DIR=/workspace/target/build-loop-real \
  tools/build-loop/measure /workspace crates/ace-results/src/lib.rs \
  /workspace/target/build-loop-results-shared 5
rm -rf /workspace/target/build-loop-real /workspace/target/build-loop-results-* /sccache/build-loop
```

The second run's edit rows are the `edit-shared` rows in `build-loop-1.31-workspace.tsv`.
