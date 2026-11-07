# Vendored crates

## qpdf-sys

`qpdf-sys/` is qpdf-sys 0.3.7 from crates.io (ancwrd1/qpdf-rs, the qpdf crate's binding), which bundles libqpdf 12.4.2, zlib and libjpeg. The root `Cargo.toml` puts it in place of the crates.io copy with `[patch.crates-io]` and leaves it out of the workspace. libqpdf 12.4.2 is what pikepdf 10.17.0 bundles, so the port and the library it's compared with are the same code.

It differs from upstream in two ways, and otherwise only in leaving out what the build doesn't compile: the Windows, macOS and arm32 bindings, and libqpdf's, zlib's and libjpeg's tests, tools and manuals.

- `bindings/aarch64-unknown-linux-gnu.rs` is regenerated. Upstream's came from bindgen 0.60 at libqpdf 12.4.0 and has `extern "C"` blocks without `unsafe`, which don't compile in the crate's edition, 2024, so the crates.io release doesn't build on arm64 Linux. This one is bindgen 0.73.2's output, from `build.rs` with the file removed and `LIBCLANG_PATH=/usr/lib/llvm-19/lib`, so `QPDF_VERSION` is right too. x86-64's is upstream's, and says 12.4.0 where the code is 12.4.2; nothing reads it.
- `build.rs` defines `USE_INSECURE_RANDOM` and `SKIP_OS_SECURE_RANDOM`, so libqpdf never opens `/dev/urandom`, which Landlock refuses a contained task (PLAN.md 2.18). It would fail at opening any AES-256 file: checking `/Perms` fills four unused bytes with random ones. Nothing here depends on the randomness. libqpdf otherwise wants it for an encrypted file's keys and IVs, and this module never writes one. Any other use of this crate would have to think again.

Its licences: the crate is MIT or Apache-2.0 by its `Cargo.toml`, libqpdf is Apache-2.0 (`qpdf/LICENSE.txt`, `qpdf/NOTICE.md`), and zlib and libjpeg are under their own (`zlib/LICENSE`, `jpeg/README`).

To update: copy the new release from the cargo registry over `qpdf-sys/`, remove what the build doesn't compile, reapply the two changes, change the versions above, check `pikepdf.__libqpdf_version__` still matches, and run `tools/library-diff/run pikepdf --right rust:ace-mod-pdf/pikepdf` and `crates/ace-pool/tests/supervisor.rs`, which reads an AES-256 file in a contained task. `crates/ace-mod-pdf` pins the exact version.

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
