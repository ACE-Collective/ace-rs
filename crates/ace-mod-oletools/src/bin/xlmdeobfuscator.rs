//! XLMMacroDeobfuscator's side of `tools/library-diff/run`, what `adapters/xlmdeobfuscator.py` does.

use std::time::{Duration, Instant};

use ace_mod_oletools::xlmdeob::run_command_on;
use ace_results::bytes::Bytes;
use serde_json::{Value, json};

const TIMEOUT: Duration = Duration::from_secs(30);
/// What adapters/side.py and adapters/xlmdeobfuscator.py put under the command's `main`.
fn frames() -> usize {
    std::env::var("XLM_FRAMES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(ADAPTER_FRAMES)
}
const ADAPTER_FRAMES: usize = 7;

fn one_pass(data: &[u8], path: &str, extract_only: bool) -> Value {
    let pass = run_command_on(
        data,
        path,
        extract_only,
        Some(Instant::now() + TIMEOUT),
        frames(),
    );
    if pass.dropped {
        return json!({"timed_out": true});
    }
    json!({"timed_out": false, "stdout": Bytes(pass.stdout.into_bytes())})
}

fn main() {
    let path = std::env::args().nth(1).expect("a file");
    let data = std::fs::read(&path).expect("a readable file");
    let emulation = one_pass(&data, &path, false);
    let cells = one_pass(&data, &path, true);
    let mut reply = json!({"output": {"emulation": emulation, "cells": cells}});
    let content = [
        &emulation_of(&reply, "emulation"),
        &emulation_of(&reply, "cells"),
    ]
    .iter()
    .any(|text| text.contains("CELL:"));
    if !content {
        reply["content"] = json!(false);
    }
    println!("{reply}");
}

fn emulation_of(reply: &Value, name: &str) -> String {
    let encoded = reply["output"][name]["stdout"]["base64"]
        .as_str()
        .unwrap_or("");
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap_or_default();
    String::from_utf8_lossy(&bytes).into_owned()
}
