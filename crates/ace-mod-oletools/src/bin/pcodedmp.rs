//! pcodedmp's side of `tools/library-diff/run`, what `adapters/pcodedmp.py` does with the library.

use ace_mod_oletools::olevba::pcodedmp_process_file;
use serde_json::json;

fn main() {
    let path = std::env::args().nth(1).expect("a file");
    let data = std::fs::read(&path).expect("a readable file");
    let (text, errors) = pcodedmp_process_file(&path, data, false);
    let mut reply = json!({"output": {"text": text, "errors": errors}});
    if text.matches('\n').count() <= 1 {
        reply["content"] = json!(false);
    }
    println!("{reply}");
}
