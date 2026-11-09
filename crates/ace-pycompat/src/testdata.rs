//! Helpers for the differential tests, which compare each function with Python on the case files
//! `tables/cases` writes to `tests/data`.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::PyErr;

/// A case file: `tests/data/NAME.json` as compiled in, or `NAME.json` in the directory
/// `ACE_PYCOMPAT_CASES` names, relative to this crate (cargo runs tests there). That is how the
/// full sets `ACE_PYCOMPAT_FULL=1 tables/cases` writes to `tests/full` are run. Run-length encoded
/// strings, `{"$rle": [[text, count], ...]}`, are expanded.
pub(crate) fn load(name: &str, embedded: &str) -> Value {
    let v: Value = match std::env::var_os("ACE_PYCOMPAT_CASES") {
        Some(dir) => {
            let path = std::path::Path::new(&dir).join(format!("{name}.json"));
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            serde_json::from_str(&text).unwrap()
        }
        None => serde_json::from_str(embedded).unwrap(),
    };
    expand(v)
}

fn expand(v: Value) -> Value {
    match v {
        Value::Object(mut m) => {
            if m.len() == 1
                && let Some(Value::Array(runs)) = m.get("$rle")
            {
                let mut s = String::new();
                for run in runs {
                    let n = run[1].as_u64().unwrap() as usize;
                    s.push_str(&run[0].as_str().unwrap().repeat(n));
                }
                return Value::String(s);
            }
            for (_, x) in m.iter_mut() {
                *x = expand(std::mem::take(x));
            }
            Value::Object(m)
        }
        Value::Array(a) => Value::Array(a.into_iter().map(expand).collect()),
        other => other,
    }
}

/// Every code point but the surrogates, as Python's case generators walk them.
pub(crate) fn all_chars() -> impl Iterator<Item = char> {
    (0..=0x10FFFF_u32).filter_map(char::from_u32)
}

/// The digest `cases_common.digest` makes: SHA-256 over each part followed by NUL.
pub(crate) fn digest<I, S>(parts: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_ref().as_bytes());
        h.update([0]);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// A string field of a case.
pub(crate) fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} isn't a string in {v}"))
}

/// Bytes given as hex.
pub(crate) fn hex(v: &Value, key: &str) -> Vec<u8> {
    let h = s(v, key);
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

/// An exception as `cases_common.err` writes it.
pub(crate) fn err_json(e: &PyErr) -> Value {
    serde_json::json!({"module": e.module, "kind": e.kind, "message": e.message})
}

/// `{"ok": value}` or `{"err": exception}`, as `cases_common.run` writes it.
pub(crate) fn outcome<T, F: FnOnce(T) -> Value>(r: Result<T, PyErr>, ok: F) -> Value {
    match r {
        Ok(v) => serde_json::json!({ "ok": ok(v) }),
        Err(e) => serde_json::json!({ "err": err_json(&e) }),
    }
}

/// Collects mismatches and fails with the first few, so one run shows how widespread a bug is.
pub(crate) struct Mismatches {
    what: &'static str,
    seen: usize,
    total: usize,
    shown: Vec<String>,
}

impl Mismatches {
    pub(crate) fn new(what: &'static str) -> Self {
        Self {
            what,
            seen: 0,
            total: 0,
            shown: Vec::new(),
        }
    }

    pub(crate) fn check(&mut self, input: impl std::fmt::Debug, got: &Value, want: &Value) {
        self.total += 1;
        if got != want {
            self.seen += 1;
            if self.shown.len() < 8 {
                self.shown
                    .push(format!("input {input:?}\n   got {got}\n  want {want}"));
            }
        }
    }

    pub(crate) fn finish(self) {
        assert!(self.total > 0, "{}: no cases", self.what);
        assert!(
            self.seen == 0,
            "{}: {} of {} cases differ from Python:\n{}",
            self.what,
            self.seen,
            self.total,
            self.shown.join("\n")
        );
    }
}
