//! Builds libxml2 from `vendor/libxml2/` (see `vendor/README.md`), statically, with the
//! `config.h` and `xmlversion.h` its configure wrote for the features this crate uses.

use std::path::PathBuf;

const SOURCES: &[&str] = &[
    "HTMLparser.c",
    "HTMLtree.c",
    "SAX2.c",
    "buf.c",
    "chvalid.c",
    "dict.c",
    "encoding.c",
    "entities.c",
    "error.c",
    "globals.c",
    "hash.c",
    "list.c",
    "parser.c",
    "parserInternals.c",
    "threads.c",
    "tree.c",
    "uri.c",
    "valid.c",
    "xmlIO.c",
    "xmlmemory.c",
    "xmlsave.c",
    "xmlstring.c",
];

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vendor/libxml2");
    let mut build = cc::Build::new();
    build
        .include(&root)
        .include(root.join("include"))
        .define("HAVE_CONFIG_H", None)
        .define("SYSCONFDIR", "\"/usr/local/etc\"")
        // libxml2's own flags; its warnings are upstream's
        .opt_level(2)
        .warnings(false);
    for source in SOURCES {
        let path = root.join(source);
        println!("cargo:rerun-if-changed={}", path.display());
        build.file(path);
    }
    println!("cargo:rerun-if-changed={}", root.join("config.h").display());
    println!("cargo:rerun-if-changed={}", root.join("include").display());
    build.compile("xml2");
    println!("cargo:rustc-link-lib=m");
}
