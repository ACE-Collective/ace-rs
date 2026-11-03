# Vendored crates

## unrar_sys

`unrar_sys/` is unrar_sys 0.5.8 from crates.io (muja/unrar.rs at commit `8fe13978`), which
bundles RARLAB's UnRAR source, version 7.1 (2024), in `unrar_sys/vendor/unrar/`. The root
`Cargo.toml` puts it in place of the crates.io copy with `[patch.crates-io]` and leaves it out of
the workspace.

It differs from upstream in one line: `build.rs` no longer defines `RAR_SMP`. With `RAR_SMP`,
unrar starts a thread per CPU to unpack a RAR 5 archive, and a contained task process can't
start threads (PLAN.md 2.17, 2.18). Without it, unrar unpacks on the calling thread. Nothing
else defines `RAR_SMP` outside Windows (`vendor/unrar/os.hpp` sets it only under `_WIN_ALL`).

The crate is MIT OR Apache-2.0, as its `Cargo.toml` says; the crates.io package carries no
license files of its own. UnRAR's license is `unrar_sys/vendor/unrar/license.txt`.

To update: copy the new unrar_sys release from the cargo registry over `unrar_sys/`, remove the
`.define("RAR_SMP", None)` line from its `build.rs` again, change the versions above, and run
the archive module's tests and `crates/ace-pool/tests/supervisor.rs`, which unpacks a RAR 5
archive in a contained task process.
