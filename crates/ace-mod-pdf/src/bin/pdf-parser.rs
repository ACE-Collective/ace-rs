//! The Rust side of `tools/library-diff/run pdf-parser`: what
//! `tools/library-diff/adapters/pdf-parser.py` records of a run of the script, from its port. The
//! limits are far off, since the script has none and the comparison gives it two minutes.
//! `--task-limits` after the file uses a task's, for `docs/measurements/pdf-hostile.md`.

use std::time::Duration;

use ace_mod_pdf::objects::bytes_json;
use ace_mod_pdf::pdfparser::Limits;
use ace_mod_pdf::{run_pdfparser_on, side};
use serde_json::json;

const LIMITS: Limits = Limits {
    time: Duration::from_secs(3600),
    output_bytes: 2 << 30,
    decoded_bytes: 2 << 30,
    object_tokens: usize::MAX,
};

fn main() {
    let path = std::env::args().nth(1).expect("a file");
    let data = std::fs::read(&path).expect("the file reads");
    let limits = if std::env::args().nth(2).as_deref() == Some("--task-limits") {
        Limits::TASK
    } else {
        LIMITS
    };
    let run = run_pdfparser_on(&data, &path, &limits);
    let has_content = run.stdout.windows(4).any(|w| w == b"obj ");
    let mut reply = json!({"output": {
        "exit": run.exit(),
        "stderr": run.stderr(),
        "stdout": bytes_json(run.stdout),
    }});
    if !has_content {
        reply["content"] = json!(false);
    }
    side::answer(&reply);
}
