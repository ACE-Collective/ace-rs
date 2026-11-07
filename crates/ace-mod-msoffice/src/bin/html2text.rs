//! html2text's side of `tools/library-diff/run`, what `adapters/html2text.py` does with the library.

use ace_mod_msoffice::html2text::html2text;
use ace_mod_msoffice::read_text;
use ace_mod_oletools::py::strip;
use serde_json::json;

fn main() {
    let path = std::env::args().nth(1).expect("a file");
    let data = std::fs::read(path).expect("a readable file");
    let reply = match html2text(&read_text(&data)) {
        Ok(text) if strip(&text).is_empty() => json!({"output": text, "content": false}),
        Ok(text) => json!({"output": text}),
        Err(error) => json!({"error": {"type": error.kind, "message": error.message}}),
    };
    println!("{reply}");
}
