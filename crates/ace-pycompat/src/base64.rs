//! `base64.b64decode` and `base64.urlsafe_b64decode` of Python 3.14, on a str or bytes.
//!
//! A str with a non-ASCII character raises `ValueError`. Decoding is `binascii.a2b_base64` in its
//! default, non-strict mode: characters outside the alphabet are skipped, a `=` is skipped wherever
//! it is, and decoding goes on after padding. Only the end is checked: one data character more than
//! a multiple of four, or too little padding, raises `binascii.Error`, a `ValueError`.

use crate::PyErr;

fn binascii_error(message: impl Into<String>) -> PyErr {
    PyErr::new("binascii", "Error", message)
}

fn ascii(s: &str) -> Result<&[u8], PyErr> {
    if s.is_ascii() {
        Ok(s.as_bytes())
    } else {
        Err(PyErr::value_error(
            "string argument should contain only ASCII characters",
        ))
    }
}

/// `base64.b64decode(s)` for a str.
pub fn b64decode(s: &str) -> Result<Vec<u8>, PyErr> {
    a2b_base64(ascii(s)?)
}

/// `base64.urlsafe_b64decode(s)` for a str.
pub fn urlsafe_b64decode(s: &str) -> Result<Vec<u8>, PyErr> {
    urlsafe_b64decode_bytes(ascii(s)?)
}

/// `base64.b64decode(b)` for bytes.
pub fn b64decode_bytes(b: &[u8]) -> Result<Vec<u8>, PyErr> {
    a2b_base64(b)
}

/// `base64.urlsafe_b64decode(b)` for bytes.
pub fn urlsafe_b64decode_bytes(b: &[u8]) -> Result<Vec<u8>, PyErr> {
    let translated: Vec<u8> = b
        .iter()
        .map(|&c| match c {
            b'-' => b'+',
            b'_' => b'/',
            _ => c,
        })
        .collect();
    a2b_base64(&translated)
}

fn value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// `binascii.a2b_base64(data)`, not strict.
pub fn a2b_base64(data: &[u8]) -> Result<Vec<u8>, PyErr> {
    let mut out = Vec::with_capacity(data.len() / 4 * 3 + 3);
    let mut quad_pos = 0;
    let mut leftchar: u8 = 0;
    let mut pads = 0;
    for &c in data {
        if c == b'=' {
            pads += 1;
            continue;
        }
        let Some(v) = value(c) else {
            continue;
        };
        pads = 0;
        match quad_pos {
            0 => {
                quad_pos = 1;
                leftchar = v;
            }
            1 => {
                quad_pos = 2;
                out.push((leftchar << 2) | (v >> 4));
                leftchar = v & 0x0f;
            }
            2 => {
                quad_pos = 3;
                out.push((leftchar << 4) | (v >> 2));
                leftchar = v & 0x03;
            }
            _ => {
                quad_pos = 0;
                out.push((leftchar << 6) | v);
                leftchar = 0;
            }
        }
    }
    if quad_pos == 1 {
        return Err(binascii_error(format!(
            "Invalid base64-encoded string: number of data characters ({}) cannot be 1 more than a multiple of 4",
            out.len() / 3 * 4 + 1
        )));
    }
    if quad_pos != 0 && quad_pos + pads < 4 {
        return Err(binascii_error("Incorrect padding"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::pystr::decode_ascii;
    use crate::testdata::{Mismatches, outcome, s};

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn decoding_matches_python() {
        let data: Value =
            crate::testdata::load("base64", include_str!("../tests/data/base64.json"));
        let mut m = Mismatches::new("base64");
        for case in data.as_array().unwrap() {
            let x = s(case, "s");
            let padded = format!("{x}===");
            let got = json!({
                "s": x,
                "b64": outcome(b64decode(x), |b| json!(hex(&b))),
                "urlsafe": outcome(urlsafe_b64decode(x), |b| json!(hex(&b))),
                "padded_ascii": outcome(b64decode(&padded).and_then(|b| decode_ascii(&b).map(str::to_owned)), |v| json!(v)),
                "urlsafe_padded_ascii": outcome(urlsafe_b64decode(&padded).and_then(|b| decode_ascii(&b).map(str::to_owned)), |v| json!(v)),
            });
            m.check(x, &got, case);
        }
        m.finish();
    }
}
