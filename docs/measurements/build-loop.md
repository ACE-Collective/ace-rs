# Build loop

PLAN.md step 0.5 times the build loop on a throwaway workspace that uses tokio, axum, sqlx, askama, the AWS S3 SDK and yara-x once each, before any ACE code exists. Step 1.31 repeats the measurements on the real workspace and adds them here.

## What was measured

`tools/build-loop/make-spike` writes the spike: a Cargo workspace outside ace4's members with two crates. `spike-deps` uses the six libraries, and `spike-leaf` depends on it and holds one test that calls into all six, so its test binary links them. The build compiles 406 crates. The spike was deleted after the runs, and `make-spike` recreates it.

`tools/build-loop/measure` times one command in every run, `cargo test --workspace --no-run --frozen`, which ends with runnable test binaries. It runs four series of five runs:

- **clean-cold:** after `cargo clean`, with sccache's cache emptied first.
- **clean-warm:** after `cargo clean`, with sccache's cache kept from the run before.
- **noop:** with nothing changed since the last build.
- **edit:** after rewriting one line, `pub const EDIT_MARKER: u32 = N;`, in `spike-leaf/src/lib.rs`. Cargo recompiles `spike-leaf` and relinks its 614 MB test binary.

Versions: Rust 1.99.1, tokio 1.54.1, axum 0.8.9, sqlx 0.9.0 (postgres, macros, rustls on aws-lc-rs), askama 0.16.1, aws-sdk-s3 1.156.0 (default features, without aws-config) and yara-x 1.22.1 (default features). The dev profile is Cargo's default, with debuginfo and incremental compilation of workspace crates.

## Dev container on macOS

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

## CI's Linux runner

Pending. The `build-loop` workflow (`.github/workflows/build-loop.yml`) runs the same two scripts inside the dev image on GitHub's `ubuntu-24.04` runner, by hand from the Actions tab, and writes the same table to the run's summary. It hasn't run yet, because this checkout has no GitHub repository.

## How to rerun

In the dev container:

```sh
tools/build-loop/make-spike spike-build-loop
CARGO_TARGET_DIR=/workspace/target/build-loop-spike \
  tools/build-loop/measure spike-build-loop spike-build-loop/spike-leaf/src/lib.rs \
  /workspace/target/build-loop-results 5
rm -rf spike-build-loop /workspace/target/build-loop-spike /sccache/build-loop
```

`measure` gives sccache its own cache directory, `$SCCACHE_DIR/build-loop`, so emptying it for the clean-cold series leaves the dev container's cache alone.
