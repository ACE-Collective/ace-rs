//! Compares [`analyze`](crate::analyze) with LnkParse3's answers recorded by
//! `tests/data/oracle.py` in ace-dev-1: the hand-built cases in full, the mutations by digest.

use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{Outcome, PyValue, analyze, to_ace3_json};

const CASES: &str = include_str!("../tests/data/cases.json");

/// `json.dumps(info, cls=_JSONEncoder, ensure_ascii=False, separators=(",", ":"))`, dict order kept.
fn py_compact(v: &PyValue, out: &mut String) {
    fn s(text: &str, out: &mut String) {
        out.push('"');
        for c in text.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{8}' => out.push_str("\\b"),
                '\u{c}' => out.push_str("\\f"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
    }
    match v {
        PyValue::None => out.push_str("null"),
        PyValue::Int(i) => out.push_str(&i.to_string()),
        PyValue::Str(t) => s(t, out),
        PyValue::DateTime(d) => s(&d.ace3_format(), out),
        PyValue::List(l) => {
            out.push('[');
            for (i, x) in l.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                py_compact(x, out);
            }
            out.push(']');
        }
        PyValue::Dict(d) => {
            out.push('{');
            for (i, (k, x)) in d.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                s(k, out);
                out.push(':');
                py_compact(x, out);
            }
            out.push('}');
        }
    }
}

fn sha(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn apply(data: &[u8], op: &[Value]) -> Vec<u8> {
    let n = |i: usize| usize::try_from(op[i].as_u64().unwrap()).unwrap();
    let mut d = data.to_vec();
    match op[0].as_str().unwrap() {
        "s" => d[n(1)] = u8::try_from(n(2)).unwrap(),
        "t" => d.truncate(n(1)),
        "d" => {
            let end = (n(1) + n(2)).min(d.len());
            d.drain(n(1)..end);
        }
        "i" => {
            let hex = op[2].as_str().unwrap();
            let raw: Vec<u8> = (0..hex.len() / 2)
                .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
                .collect();
            let at = n(1);
            if op.len() > 3 {
                let end = (at + raw.len()).min(d.len());
                d.splice(at..end, raw);
            } else {
                d.splice(at..at, raw);
            }
        }
        other => panic!("op {other}"),
    }
    d
}

fn error_of(o: &Outcome) -> Value {
    o.error.as_ref().map_or(
        Value::Null,
        |e| serde_json::json!({"type": e.kind, "message": e.message}),
    )
}

#[test]
fn matches_lnkparse3() {
    let cases: Value = serde_json::from_str(CASES).unwrap();
    let mut bases = Vec::new();
    let mut failures = Vec::new();
    for b in cases["base"].as_array().unwrap() {
        let name = b["name"].as_str().unwrap();
        let data = base64::engine::general_purpose::STANDARD
            .decode(b["data"].as_str().unwrap())
            .unwrap();
        let o = analyze(&data);
        let mut info = String::new();
        py_compact(&o.info, &mut info);
        let want_info = b["info"].as_str().unwrap();
        if info != want_info {
            failures.push(format!("{name}: info\n  got  {info}\n  want {want_info}"));
        }
        let parsed: Value = serde_json::from_str(want_info).unwrap();
        if to_ace3_json(&o.info) != parsed {
            failures.push(format!("{name}: to_ace3_json"));
        }
        if error_of(&o) != b["error"] {
            failures.push(format!("{name}: error {:?} want {}", o.error, b["error"]));
        }
        if o.command.as_deref() != b["command"].as_str() {
            failures.push(format!(
                "{name}: command {:?} want {}",
                o.command, b["command"]
            ));
        }
        if o.lnkparser_json.as_deref() != b["dump"].as_str() {
            failures.push(format!(
                "{name}: dump\n  got  {:?}\n  want {}",
                o.lnkparser_json, b["dump"]
            ));
        }
        bases.push(data);
    }
    let muts = cases["mutations"].as_array().unwrap();
    for (i, m) in muts.iter().enumerate() {
        let mut data = bases[usize::try_from(m["base"].as_u64().unwrap()).unwrap()].clone();
        for op in m["ops"].as_array().unwrap() {
            data = apply(&data, op.as_array().unwrap());
        }
        let o = analyze(&data);
        let mut info = String::new();
        py_compact(&o.info, &mut info);
        let mut bad = Vec::new();
        if sha(&info) != m["info_sha256"].as_str().unwrap() {
            bad.push("info");
        }
        if error_of(&o) != m["error"] {
            bad.push("error");
        }
        if o.command.as_deref() != m["command"].as_str() {
            bad.push("command");
        }
        if o.lnkparser_json.as_deref().map(sha).as_deref() != m["dump_sha256"].as_str() {
            bad.push("dump");
        }
        if !bad.is_empty() {
            failures.push(format!(
                "mutation {i}: {bad:?} error {:?} want {}",
                o.error, m["error"]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ:\n{}",
        failures.len(),
        bases.len() + muts.len(),
        failures.join("\n")
    );
}
