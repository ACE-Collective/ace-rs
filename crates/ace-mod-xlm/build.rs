//! Compiles ace3's `src/xlmdeobfuscator.yar` and serializes the rules with their machine code, so a
//! parser task, a process of its own, loads them in a quarter of a millisecond instead of compiling
//! them in four. yara-x is a build dependency at the version the crate runs, with
//! `native-code-serialization`, which only serializing needs: loading reads machine code whatever
//! yara-x's features. Where the machine code doesn't suit the process (another CPU, or a wasmtime
//! built differently), yara-x compiles the rules' WebAssembly again itself; where the rules don't
//! load at all (yara-x's rule profiling on in one build and not the other), `lib.rs` compiles the
//! source. Its tests check that the rules built here are the ones the source compiles to.

use std::path::PathBuf;

const RULES: &str = "src/xlmdeobfuscator.yar";

fn main() {
    println!("cargo::rerun-if-changed={RULES}");
    let source = std::fs::read_to_string(RULES).expect("reading the rule file");
    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(source.as_str())
        .expect("compiling the rule file");
    let bytes = compiler.build().serialize().expect("serializing the rules");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    std::fs::write(out.join("xlmdeobfuscator.yarc"), bytes).expect("writing the rules");
}
