# Office decryption in Rust

PLAN.md 4.11 asks how fast passwords go in Rust, whether 4.6's 240 s deadline can come down to ace3's 60 s, whether a spin count of 2^31-1 still stops, and what the file tasks' wait for an email costs the comparison.

All of this ran on 2026-11-07, on the dev container of `docs/measurements/build-loop.md`: Rancher Desktop's Linux 6.18 on arm64, 10 CPUs, whose `/proc/cpuinfo` lists `sha512`. ace3's and budge's stacks were idle on the same VM. Nothing here is measured on amd64.

## How fast

`cargo build --release -p ace-mod-msoffice --bin msoffcrypto`, then `msoffcrypto --rate FILE 500`, which tries that many wrong passwords as the module does: three runs of each, one thread, no containment, which is key derivation and a verifier check and nothing else.

| File | Kind | Spin count | Median a second | Range |
|---|---|---:|---:|---|
| `encrypted_agile.docx` | Agile, SHA-512, AES-256 | 100,000 | 116 | 115 to 116 |
| `msoffcrypto_example_password.docx` | the same, written by Office | 100,000 | 115 | 114 to 115 |
| `encrypted_agile_sha256.docx` | Agile, SHA-256 | 100,000 | 286 | 283 to 287 |
| `encrypted_standard.docx` | Standard, SHA-1 | 50,000 | 491 | 484 to 502 |
| `encrypted_cryptoapi.doc` | RC4 with CryptoAPI | none | 786,000 | 761,000 to 797,000 |

4.6 measured about 30 Agile passwords a second in Python on the same machine. John gets about 51 a thread. `msoffcrypto --rate encrypted_agile.docx 5000`, one run, took 43.3 s.

**In a contained task.** `cargo test --release -p ace-pool --features test-pools --test supervisor measure_msoffice -- --ignored --nocapture` submits an email holding Office 2013's encryption and a body of 1,200 characters with no whitespace, whose list is 5,002 passwords with the two defaults, to the real supervisor, with the email module and this one, single-threaded, under Landlock, seccomp and the module's limits. It times the root from submission to idle, so it includes the email's parsing and the task's start. Three runs: median 43.8 s, range 43.4 s to 45.4 s.

## The deadline

It's 150 s, down from 240 s. It isn't ace3's 60 s, and the owner's question about it remains, smaller:

- 45 s of 60 s isn't well within it. It leaves 15 s on the one machine measured, and that machine has SHA-512 instructions.
- amd64 mostly hasn't them. Software SHA-512 at about 5 cycles a byte on a 3 GHz machine is about 210 ns a block, against 86 ns here, which would make the full list about 105 s. That's an estimate, not a measurement: there's no amd64 machine here. At 60 s such a machine stops partway down a list John finishes in 10 s on ten threads.
- A list that long is rare. Windows of 4 to 11 characters only make 5,000 passwords out of text with little whitespace: an ordinary body of 1,024 characters makes under 1,000, about 9 s here, and about 20 s by that estimate. So 60 s would mostly work, and fail on the bodies most likely to be crafted.

Measure amd64 on the first real deployment. If the list takes under 30 s there, set the deadline to 60 s and drop the difference.

## A spin count of 2^31-1

The module stops itself with `AFTER_CRACKING`, 5 s before the deadline, looking at the clock every 4,096 spins and between passwords, with no signal and no thread. The same test's second file is that file with a spin count of 2^31-1, which at this rate is about 3 minutes for one password: three runs of 145.1 s, each from submission to idle, with `could not crack password` in the result, and the supervisor's kill not reached. Decrypting a file of 264 MB and writing its JSON took 0.7 s and 1,177 MiB at peak in `msoffcrypto`, under 2 GiB of address space, one run, against the 5 s kept for it. An OLE stream past 256 MiB raises MemoryError (`ole.rs`), so such a file keeps its password and has no decrypted file, as 4.6's did at 258 MB.

## The comparison's wait

Before this, the core delayed every file task of this module for 1 s or more while the root had an email task unfinished, because the email module takes every file. Now the core tells the module the email isn't parsed yet (`LeasedTask::emails_pending`) and the module opens the file first. A file that isn't encrypted is done, and only an encrypted one delays itself.

`tests/e2e/run --compare`, one run each, on the same machine and from a stack it builds itself:

| | Samples | `ace compare`'s seconds | Mean a sample | Whole script |
|---|---:|---:|---:|---:|
| Before, at 4.10's commit | 267 | 633 | 2.4 s | 671 s |
| After | 326 | 313 | 1.0 s | 371 s |

Some of that is the move itself: tasks of this module no longer wait for a Python slot, and there are four parser slots to Python's two.

## The crates

`aes` 0.9.4, `cbc` 0.2.1, `sha1` 0.11.0, `sha2` 0.11.1, `md-5` 0.11.0 and `rc4` 0.2.0, all RustCrypto's, on `cipher` 0.5 and `digest` 0.11. All six were published in 2026. `aes`, `cbc`, `sha1`, `sha2` and `md-5` have 53 M to 364 M recent downloads on crates.io. `rc4` has 341,000, and its release before this one was in 2022: it's RustCrypto's own, in its stream-ciphers repository, moved to `cipher` 0.5 in March 2026, and a small crate. `hmac` isn't needed: nothing ACE calls checks a package's HMAC. In a debug build these are optimized all the same (`Cargo.toml`), or the library diff and the tests time out.
