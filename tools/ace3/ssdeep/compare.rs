//! The fuzzyhash 0.2.2 side of docs/measurements/ssdeep.md, as a one-file binary crate with
//! `fuzzyhash = "0.2.2"`: each file's hash, then each file's score against each base file, as
//! `ssdeep -s -m` prints a match.

use fuzzyhash::FuzzyHash;
use std::fs;
fn main() {
    let dir = "data/files";
    let mut names: Vec<String> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    names.sort();
    let mut hashes = Vec::new();
    for n in &names {
        let data = fs::read(format!("{dir}/{n}")).unwrap();
        let mut h = FuzzyHash::new(&data);
        h.finalize();
        let s = h.to_string();
        println!("H {s},\"{n}\"");
        hashes.push((n.clone(), s));
    }
    let bases: Vec<&(String, String)> = hashes.iter().filter(|(n, _)| n.starts_with("base")).collect();
    for (n, h) in &hashes {
        for (bn, bh) in &bases {
            let score = FuzzyHash::compare(h, bh).unwrap_or(0);
            if score > 0 { println!("M /tmp/ace4-ssdeep/files/{n} matches ../hashes_base:/tmp/ace4-ssdeep/files/{bn} ({score})"); }
        }
    }
}
