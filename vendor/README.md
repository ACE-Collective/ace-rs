# Vendored code

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

## datastar

`datastar/datastar-1.0.4.js` is Datastar 1.0.4 (starfederation/datastar), the file ace3 vendors as
`app/static/js/datastar-1.0.4.js`, byte for byte. It's upstream's `bundles/datastar.js` at tag `v1.0.4`
(commit `1efcdc3cb336ec3e9139491604e770e0329657bc`). The GitHub release has no assets, so that file is the
published artifact. It's unchanged: 33,553 bytes, SHA-256
`727844adfc825ee651fb93c544a2a739986f9a21820a94524b35f0cac470cf91`. That hash was checked against
both `https://raw.githubusercontent.com/starfederation/datastar/v1.0.4/bundles/datastar.js` and
`https://cdn.jsdelivr.net/gh/starfederation/datastar@v1.0.4/bundles/datastar.js`, the URL
`ace3/docs/GUI_DATASTAR.md` names, and it matches the hash recorded there. There's no npm and no build
step: `ace-gui` embeds the file in the binary, and `crates/ace-gui/tests/gui.rs` fails if the bytes it
serves stop matching the hash above.

Its licence is MIT, `datastar/LICENSE.md`, upstream's `LICENSE.md` at the same tag.

To update: download `bundles/datastar.js` at the new tag from both URLs above, check they match, save it
as `datastar/datastar-<version>.js`, replace `LICENSE.md` from the same tag, and change the version,
commit and hash here and the file name in `crates/ace-gui/src/assets.rs`. ace3's `docs/GUI_DATASTAR.md`
lists the syntax that changed at 1.0: an attribute that's wrong does nothing, so check each page in a
browser.

## vis

`vis/vis-4.1.0.js` is vis.js 4.1.0 (almende/vis, now the archived visjs/vis), the library and version ace3
vendored as `app/static/js/vis.js` for its alert graph until it removed both as unused (ace3 commit
`9f63a496`, 2026-10-01). ace4 uses it for the relationship graph (PLAN.md 5.13). It's `dist/vis.js` of the
npm package `vis@4.1.0`, the release's published artifact: the tarball
`https://registry.npmjs.org/vis/-/vis-4.1.0.tgz` matches the integrity npm records for it,
`sha512-lu2jcGY8HVTysRhxCWki87pbCbFKX96zbT/fW8uLo+meJnPJMrQSfaOa7MAHm5SA1z2HAa2foToU7qTlM6GMgQ==`. The file
is unchanged: 1,385,623 bytes, SHA-256 `46976445f2254ccba5803dd9d9725fb5fccda2c88b381340046fc8cd1a225ee6`.
That hash was checked against the same file at the tag, `https://raw.githubusercontent.com/almende/vis/v4.1.0/dist/vis.js`
(commit `62a844de3fd82a571dd07a045635f277e6635735`), and `https://cdn.jsdelivr.net/npm/vis@4.1.0/dist/vis.js`.
ace3's copy is the same text with some lines ending in CRLF; this is upstream's, with LF. The GitHub tag has no
release assets. npm is used only to fetch the tarball once: there's no build step, and `ace-gui` embeds the
file in the binary. `crates/ace-gui/tests/gui.rs` fails if the bytes it serves stop matching the hash above.
The unminified build is the one ace3 vendored; the release's `vis.min.js` names a source map, `vis.map`,
that ace4 doesn't serve.

It runs under 5.7's policy unchanged, which `tests/e2e/run` checks in its browser: it has no `eval` or
`Function`, it styles what it creates through the CSSOM (`element.style`), which a policy doesn't restrict,
and the network draws on a canvas. ace4 leaves out `vis.css`, which styles only the parts the graph doesn't
use: the navigation buttons, the manipulation toolbar, the configurator and the tooltip. A node's `title`, vis's
tooltip, is set as HTML, so `crates/ace-gui/static/graph.js` never sets one.

vis 4.1.0 is from 2015 and the `vis` package is deprecated, split into vis-network and others. OSV lists no
advisory against `vis` (queried 2026-11-08). The one against a successor, vis-timeline's CVE-2020-28487, is
script injected through a timeline's items, a part of the bundle the graph doesn't use.

Its licence is MIT or Apache-2.0, at the user's choice; `vis/LICENSE-MIT` and `vis/LICENSE-APACHE-2.0` are the
package's own, identical to the tag's.

To update: download `dist/vis.js` from the npm tarball of the new version, check the tarball against the
registry's integrity and the file against the tag's, save it as `vis/vis-<version>.js`, replace both licences,
and change the version, commit and hash here and the file name in `crates/ace-gui/src/assets.rs`. Then run
`tests/e2e/run`, whose browser draws 2.30's alert with it under the policy. A later vis.js, or vis-network,
may set `title` or labels differently, so read `graph.js` against its documentation first.

## libxml2

`libxml2/` is libxml2 2.14.6, the release lxml 6.1.3's wheels bundle (`lxml.etree.LIBXML_VERSION` in ace3's image is `(2, 14, 6)`), from `https://download.gnome.org/sources/libxml2/2.14/libxml2-2.14.6.tar.xz`, whose SHA-256, `7ce458a0affeb83f0b55f1f4f9e0e55735dbfc1a9de124ee86fb4a66b597203a`, is the one GNOME publishes beside it. `crates/ace-lxml/build.rs` compiles it with `cc`, statically, at `-O2` as lxml's build does. lxml applies no patch to libxml2.

It holds only what that build compiles: the 22 `.c` files of the library's core, HTML parser and serializer and their `.inc` tables, `libxml.h`, every public header under `include/libxml/` and the private ones under `include/private/`, and the licence, `Copyright`. Two files are generated: `config.h` and `include/libxml/xmlversion.h` are what `./configure` wrote in the dev container with `--without-python --without-iconv --without-zlib --without-lzma --with-threads --without-thread-alloc --without-http --without-catalog --without-xinclude --without-xpath --without-xptr --without-schemas --without-schematron --without-relaxng --without-regexps --without-reader --without-writer --without-pattern --without-c14n --without-modules --without-debug --without-icu --with-html --with-output --with-sax1`. lxml's build configures libxml2 with its defaults and iconv; the parser and serializer this crate uses don't depend on the features left out. A document is always parsed as UTF-8, which libxml2 decodes itself, so iconv isn't needed; a `<meta charset>` doesn't switch the encoding once one is declared, in lxml or here. Threads are on because a test process parses on several threads; libxml2 starts no thread of its own, so a contained task can run it.

Its licence is MIT, `libxml2/Copyright`.

To update: take the libxml2 release the new lxml bundles, check its SHA-256 against GNOME's, run its `configure` in the dev container with the options above, copy over the same files and the two generated ones, and run `cargo test -p ace-lxml -p ace-urlfinder`, whose cases came from ace3's lxml.
