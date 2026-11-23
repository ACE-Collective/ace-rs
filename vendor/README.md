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
`9f63a496`, 2026-10-01). ace-rs uses it for the relationship graph (PLAN.md 5.13). It's `dist/vis.js` of the
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
that ace-rs doesn't serve.

It runs under 5.7's policy unchanged, which `tests/e2e/run` checks in its browser: it has no `eval` or
`Function`, it styles what it creates through the CSSOM (`element.style`), which a policy doesn't restrict,
and the network draws on a canvas. ace-rs leaves out `vis.css`, which styles only the parts the graph doesn't
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

## unautoit

`unautoit/` is ace3's `third_party/unautoit` at ace3 `f72f8946`, byte for byte as git stores it: UnAutoIt v1.1.1 (digitalsleuth/UnAutoIt at `6c55d05`) with libautoit v1.2.8 vendored in `unautoit/third_party/libautoit`, both by x0r19x91, with the changes ace3 made in October 2026 (an output directory with mode 0755, a map for word lookups, string literals without Go's escapes). `unautoit/third_party/README.md` and ace3's `third_party/README.md` record where each came from and what changed. Both upstream repositories are gone, which is why ace3 keeps the source.

It's GPL-3 (`unautoit/LICENSE`). Nothing in ace-rs links it: `docker/ace-rs/Dockerfile`'s and `docker/dev/Dockerfile`'s `unautoit` stage builds it as ace3's Dockerfile does, libautoit's tests and then a static binary with Go 1.27.3, ace3's, `CGO_ENABLED=0` and `-trimpath`, and copies the licences of it, of Go and of each Go module it compiles in beside the binary in `/usr/local/share/doc/unautoit`. The autoit module runs it as a program of its own in the sandbox runner. The binary is ace3's: on arm64 its sha256 is `571da970839793b7fdddb2d7ab22ddb8457f2745a5b8ff273a22af4492650c77`, as in ace3's image. `go build` fetches the Go modules `go.sum` pins.

To update: copy ace3's `third_party/unautoit` over `unautoit/` again (from git, `git show`, so line endings are as stored), change the commit above, and rebuild both images; `crates/ace-pool/tests/containment.rs`'s `unautoit_lists_and_extracts_under_the_runner` and `crates/ace-mod-sandbox/tests/reference.rs` check it still runs as ace3's.

## The search index's embedding model (not in this repository)

`sentence-transformers/all-MiniLM-L6-v2` is the model ace3's alert search embeds with (`search.embedding_model`), and ace-rs's does too (PLAN.md 7.11, `crates/ace-search/src/model.rs`), so the two are compared on the same vectors. Its weights are 91 MB, so they aren't in git. The images fetch three files when they are built, from the model's own repository on Hugging Face at commit `1110a243fdf4706b3f48f1d95db1a4f5529b4d41`, each with `ADD --checksum` (the `search-model` stage of `docker/ace-rs/Dockerfile` and `docker/dev/Dockerfile`):

| File | Bytes | SHA-256 |
|---|---|---|
| `model.safetensors` | 90,868,376 | `53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db` |
| `tokenizer.json` | 466,247 | `be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037` |
| `config.json` | 612 | `953f9c0d463486b10a6871cc2fd59f223b2c70184f49815e7efbcab5d8908b41` |

They land in `/usr/local/share/ace-rs/search-model/all-MiniLM-L6-v2`, which `ACE_RS_SEARCH_MODEL` names, in the `ace-rs-ace` image, for `ace serve`, and in the dev image, for the tests. `ace_search::Model::load` checks the same three hashes before it reads a file, so a file that was swapped or cut short loads nothing. No process downloads the model: ace3's indexer fetches it when it first starts, and ace-rs's never does. The model runs in the `ace serve` process on the CPU, so nothing an alert holds is sent anywhere to be embedded.

Its licence is Apache-2.0, as the repository's model card says (`README.md` at the same commit). The repository's other files, its ONNX and OpenVINO exports, its PyTorch and TensorFlow weights and its sentence-transformers module settings, aren't fetched: the forward pass reads the safetensors file, and the pooling and the 256-token limit those settings describe are in `model.rs`.

To update: change the commit and the three hashes in both Dockerfiles and in `MODEL_REVISION` and `MODEL_FILES`, run `tools/ace3/search/make-reference` against an ace3 whose indexer has the same model, and run `ace-search`'s tests, which hold the vectors to ace3's. A different model changes every embedding, so every alert is indexed again: `INSERT INTO search.due (root_id) SELECT id FROM analysis.roots WHERE alerted_at IS NOT NULL ON CONFLICT (root_id) DO UPDATE SET version = search.due.version + 1, attempts = 0`.

## pgvector (not in this repository)

pgvector 0.8.7 is the Postgres extension the search index keeps its embeddings in (PLAN.md 7.11). `docker/postgres/Dockerfile` builds it onto the stack's pinned Postgres image from its release tarball, `https://github.com/pgvector/pgvector/archive/refs/tags/v0.8.7.tar.gz`, SHA-256 `cac0b10c360f05b2d521200105ba3697e773d4cd3731f5a915a7e37ebe0bea85`, with no `-march=native`, and puts its licence beside it. Its licence is the PostgreSQL License. The image is `ace-rs-postgres:18.6-pgvector0.8.7`, 7 MB larger than its base.

To update: change the version and the hash in the Dockerfile and the tag in `compose.yaml`, and run `ace-search`'s tests and `tests/e2e/run`. An index made by an older pgvector is read by a newer one; its changelog says when one isn't.
