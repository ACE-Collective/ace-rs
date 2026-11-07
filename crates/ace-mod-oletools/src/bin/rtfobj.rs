//! rtfobj's side of `tools/library-diff/run`, what `adapters/rtfobj.py` does with the library.

use ace_mod_oletools::rtf::{Limits, process_file};
use ace_results::bytes::Bytes;
use serde_json::{Map, Value, json};

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // what a task runs with, for measuring: the library diff runs without them
    let limits = if args.first().is_some_and(|arg| arg == "--task-limits") {
        args.remove(0);
        Limits::TASK
    } else {
        Limits::NONE
    };
    let path = args.first().expect("a file");
    let data = std::fs::read(path).expect("a readable file");
    let report = process_file(path, &data, "/tmp/rtfobj-objects", limits);
    let mut files = Map::new();
    let mut names: Vec<_> = report.files.iter().collect();
    names.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, bytes) in names {
        files.insert(name.clone(), json!(Bytes::new(bytes.clone())));
    }
    let content = !files.is_empty();
    let mut output =
        json!({"files": Value::Object(files), "stdout": Bytes::new(report.stdout.into_bytes())});
    if let Some(raised) = report.raised {
        output["raised"] = json!({"type": raised.kind, "message": raised.message});
    }
    let mut reply = json!({"output": output});
    if !content {
        reply["content"] = json!(false);
    }
    println!("{reply}");
}
