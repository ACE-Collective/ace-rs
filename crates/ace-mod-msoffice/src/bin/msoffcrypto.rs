//! msoffcrypto's side of `tools/library-diff/run`, what `adapters/msoffcrypto.py` does with the library.

use std::sync::Arc;
use std::time::Instant;

use ace_mod_msoffice::method::Stop;
use ace_mod_msoffice::office::OfficeFile;
use ace_mod_oletools::py::{PyErr, PyResult};
use ace_results::bytes::Bytes;
use serde_json::{Value, json};

const PASSWORDS: [&str; 14] = [
    "VelvetSweatshop",
    "/01Hannes Ruescher/01",
    "709384",
    "Secr3tPw",
    "St4ndard",
    "H7mlPass",
    "NotInTheBody99",
    "InnerPw1",
    "R4Binary1",
    "CryptoAp1",
    "x0rPass",
    "x0rPass8",
    "Password1234_",
    "123456789012345",
];

/// The Python frames at `OfficeFile(fp)`: `<module>`, `main`, `run` and `attempt`'s or its own caller.
const DEPTH: usize = 4;

fn raised(error: &PyErr) -> Value {
    json!({"type": error.kind, "message": error.message})
}

fn attempt(data: &Arc<Vec<u8>>, password: &str) -> PyResult<Value> {
    let mut office = OfficeFile::open(Arc::clone(data), DEPTH + 1)?;
    let mut attempt = json!({"password": password, "opens": false});
    match office.load_key(password, Stop::default()) {
        Ok(()) => {}
        Err(error) if error.kind == "InvalidKeyError" => return Ok(attempt),
        Err(error) => {
            attempt["raised"] = raised(&error);
            return Ok(attempt);
        }
    }
    attempt["opens"] = json!(true);
    match office.decrypt() {
        Ok(decrypted) => attempt["decrypted"] = json!(Bytes::new(decrypted)),
        Err(error) => attempt["raised"] = raised(&error),
    }
    Ok(attempt)
}

fn run(data: Arc<Vec<u8>>) -> PyResult<(Value, bool)> {
    let office = OfficeFile::open(Arc::clone(&data), DEPTH)?;
    let encrypted = office.is_encrypted()?;
    let mut output = json!({
        "format": office.format(),
        "type": office.kind(),
        "encrypted": encrypted,
    });
    if encrypted {
        let mut attempts = Vec::new();
        for password in PASSWORDS {
            attempts.push(attempt(&data, password)?);
        }
        output["attempts"] = json!(attempts);
    }
    Ok((output, encrypted))
}

/// `--rate FILE COUNT`: tries COUNT passwords that don't open FILE and prints how fast, as the module
/// tries them. The library diff doesn't use this.
fn rate(path: &str, count: usize) {
    let data = Arc::new(std::fs::read(path).expect("a readable file"));
    let mut office = OfficeFile::open(data, DEPTH).expect("a file it can open");
    let started = Instant::now();
    for index in 0..count {
        let password = format!("no{index}");
        match office.load_key(&password, Stop::default()) {
            Err(error) if error.kind == "InvalidKeyError" => {}
            other => panic!("{other:?}"),
        }
    }
    let seconds = started.elapsed().as_secs_f64();
    println!(
        "{count} passwords in {seconds:.2} s: {:.1} a second",
        count as f64 / seconds
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "--rate") {
        rate(&args[1], args[2].parse().expect("a count"));
        return;
    }
    let path = args.first().expect("a file");
    let data = Arc::new(std::fs::read(path).expect("a readable file"));
    let reply = match run(data) {
        Ok((output, true)) => json!({"output": output}),
        Ok((output, false)) => json!({"output": output, "content": false}),
        Err(error) => json!({"error": raised(&error)}),
    };
    println!("{reply}");
}
