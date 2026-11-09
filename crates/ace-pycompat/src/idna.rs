//! The idna package 3.20 (IDNA 2008): `idna.encode(s)` and `idna.decode(s)` with their defaults
//! (`strict=False`, `uts46=False`, `std3_rules=False`, `transitional=False`).
//!
//! Labels split on `.` and the three other dots. Each label is checked as `check_label` does: NFC,
//! hyphens, a leading combining mark, PVALID/CONTEXTJ/CONTEXTO from idnadata
//! (`tables/idnadata.py`) and the Bidi rule, with Unicode 16 properties. A label that is ASCII is
//! checked as an A-label when it starts with `xn--` and must decode and re-encode to itself.
//!
//! Errors are `idna.core.IDNAError` or a subclass of it, whose `kind` names the subclass. Punycode
//! can also raise `OverflowError` through `decode`, as Python does, and that isn't an IDNAError.

use crate::PyErr;
use crate::codecs_idna::{punycode_decode_py, punycode_encode_cps};
use crate::repr::repr_cps;
use crate::tables::idnadata as d;
use crate::tables::in_ranges;
use crate::unicodedata::{
    Form, bidirectional_cp, category_cp, combining_cp, has_name_cp, normalize_cps,
};

const MAX_INPUT: usize = 1024;
const MAX_DOMAIN: usize = 253;

fn idna_error(kind: &'static str, message: impl Into<String>) -> PyErr {
    PyErr::new("idna.core", kind, message)
}

fn error(message: impl Into<String>) -> PyErr {
    idna_error("IDNAError", message)
}

fn unot(cp: u32) -> String {
    format!("U+{cp:04X}")
}

fn is_dot(c: u32) -> bool {
    matches!(c, 0x2E | 0x3002 | 0xFF0E | 0xFF61)
}

/// `idna.encode(s)`, as the ASCII of the bytes it returns.
pub fn encode(s: &str) -> Result<String, PyErr> {
    let cps: Vec<u32> = s.chars().map(|c| c as u32).collect();
    if cps.len() > MAX_INPUT {
        return Err(error("Domain too long"));
    }
    if cps.len() > MAX_DOMAIN + 1 {
        return Err(error("Domain too long"));
    }
    let mut labels: Vec<&[u32]> = cps.split(|&c| is_dot(c)).collect();
    if labels.len() == 1 && labels[0].is_empty() {
        return Err(error("Empty domain"));
    }
    let trailing_dot = labels.last().is_some_and(|l| l.is_empty());
    if trailing_dot {
        labels.pop();
    }
    let mut result: Vec<Vec<u8>> = Vec::with_capacity(labels.len() + 1);
    for label in labels {
        let b = alabel(label)?;
        if b.is_empty() {
            return Err(error("Empty label"));
        }
        result.push(b);
    }
    if trailing_dot {
        result.push(Vec::new());
    }
    let joined = result.join(&b'.');
    if joined.len() > MAX_DOMAIN + usize::from(trailing_dot) {
        return Err(error("Domain too long"));
    }
    Ok(joined.into_iter().map(char::from).collect())
}

/// `idna.decode(s)`.
pub fn decode(s: &str) -> Result<String, PyErr> {
    let cps: Vec<u32> = s.chars().map(|c| c as u32).collect();
    if cps.len() > MAX_INPUT {
        return Err(error("Domain too long"));
    }
    if cps.len() > MAX_DOMAIN + 1 {
        return Err(error("Domain too long"));
    }
    let mut labels: Vec<&[u32]> = cps.split(|&c| is_dot(c)).collect();
    if labels.len() == 1 && labels[0].is_empty() {
        return Err(error("Empty domain"));
    }
    let trailing_dot = labels.last().is_some_and(|l| l.is_empty());
    if trailing_dot {
        labels.pop();
    }
    let mut result: Vec<String> = Vec::with_capacity(labels.len() + 1);
    for label in labels {
        let u = ulabel_str(label)?;
        if u.is_empty() {
            return Err(error("Empty label"));
        }
        result.push(u.into_iter().filter_map(char::from_u32).collect());
    }
    if trailing_dot {
        result.push(String::new());
    }
    Ok(result.join("."))
}

/// `alabel(label)`.
fn alabel(label: &[u32]) -> Result<Vec<u8>, PyErr> {
    if label.len() > MAX_INPUT {
        return Err(error("Label too long"));
    }
    if label.iter().all(|&c| c < 0x80) {
        let bytes: Vec<u8> = label.iter().map(|&c| c as u8).collect();
        ulabel_bytes(&bytes)?;
        if bytes.len() > 63 {
            return Err(error("Label too long"));
        }
        return Ok(bytes);
    }
    check_label(label)?;
    let mut out = b"xn--".to_vec();
    out.extend(punycode_encode_cps(label));
    if out.len() > 63 {
        return Err(error("Label too long"));
    }
    Ok(out)
}

/// `ulabel(label)` for a str.
fn ulabel_str(label: &[u32]) -> Result<Vec<u32>, PyErr> {
    if label.len() > MAX_INPUT {
        return Err(error("Label too long"));
    }
    if !label.iter().all(|&c| c < 0x80) {
        check_label(label)?;
        return Ok(label.to_vec());
    }
    let bytes: Vec<u8> = label.iter().map(|&c| c as u8).collect();
    ulabel_bytes(&bytes)
}

/// `ulabel(label)` from where the label is ASCII bytes.
fn ulabel_bytes(label: &[u8]) -> Result<Vec<u32>, PyErr> {
    if label.len() > MAX_INPUT {
        return Err(error("Label too long"));
    }
    let lowered = label.to_ascii_lowercase();
    let Some(rest) = lowered.strip_prefix(b"xn--") else {
        let cps: Vec<u32> = lowered.iter().map(|&b| u32::from(b)).collect();
        check_label(&cps)?;
        return Ok(cps);
    };
    if rest.is_empty() {
        return Err(error(
            "Malformed A-label, no Punycode eligible content found",
        ));
    }
    if rest.ends_with(b"-") {
        return Err(error("A-label must not end with a hyphen"));
    }
    let decoded = match punycode_decode_py(rest) {
        Ok(d) => d,
        Err(e) if e.is_instance("builtins", "UnicodeError") => {
            return Err(error("Invalid A-label"));
        }
        Err(e) => return Err(e),
    };
    if punycode_encode_cps(&decoded) != rest {
        return Err(error(
            "A-label is not the canonical Punycode encoding of its U-label",
        ));
    }
    check_label(&decoded)?;
    Ok(decoded)
}

/// `check_label(label)`.
fn check_label(label: &[u32]) -> Result<(), PyErr> {
    if label.len() > MAX_INPUT {
        return Err(error("Label too long"));
    }
    if label.is_empty() {
        return Err(error("Empty Label"));
    }
    if label.len() > MAX_DOMAIN + 1 {
        return Err(error("Label too long"));
    }
    // check_nfc
    if label.iter().any(|&c| c >= 0x80)
        && normalize_cps(Form::Nfc, label.iter().copied(), false) != label
    {
        return Err(error("Label must be in Normalization Form C"));
    }
    // check_hyphen_ok
    if label.len() >= 4 && label[2] == 0x2D && label[3] == 0x2D {
        return Err(error(
            "Label has disallowed hyphens in 3rd and 4th position",
        ));
    }
    if label[0] == 0x2D || label[label.len() - 1] == 0x2D {
        return Err(error("Label must not start or end with a hyphen"));
    }
    // check_initial_combiner
    if category_cp(label[0]).starts_with('M') {
        return Err(error("Label begins with an illegal combining character"));
    }
    for (pos, &cp) in label.iter().enumerate() {
        if in_ranges(d::PVALID, cp) {
            continue;
        }
        if in_ranges(d::CONTEXTJ, cp) {
            match valid_contextj(label, pos) {
                Err(()) => {
                    return Err(error(format!(
                        "Unknown codepoint adjacent to joiner {} at position {} in {}",
                        unot(cp),
                        pos + 1,
                        repr_cps(label)
                    )));
                }
                Ok(false) => {
                    return Err(idna_error(
                        "InvalidCodepointContext",
                        format!(
                            "Joiner {} not allowed at position {} in {}",
                            unot(cp),
                            pos + 1,
                            repr_cps(label)
                        ),
                    ));
                }
                Ok(true) => {}
            }
        } else if in_ranges(d::CONTEXTO, cp) {
            if !valid_contexto(label, pos) {
                return Err(idna_error(
                    "InvalidCodepointContext",
                    format!(
                        "Codepoint {} not allowed at position {} in {}",
                        unot(cp),
                        pos + 1,
                        repr_cps(label)
                    ),
                ));
            }
        } else {
            return Err(idna_error(
                "InvalidCodepoint",
                format!(
                    "Codepoint {} at position {} of {} not allowed",
                    unot(cp),
                    pos + 1,
                    repr_cps(label)
                ),
            ));
        }
    }
    check_bidi(label)
}

/// `_combining_class(cp)`: `Err` for Python's ValueError, a code point with no name.
fn combining_class(cp: u32) -> Result<u8, ()> {
    let v = combining_cp(cp);
    if v == 0 && !has_name_cp(cp) {
        return Err(());
    }
    Ok(v)
}

fn joining_type(cp: u32) -> Option<char> {
    d::JOINING_TYPES
        .iter()
        .find(|(_, ranges)| in_ranges(ranges, cp))
        .map(|&(jt, _)| jt)
}

/// `valid_contextj(label, pos)`: `Err` where Python raises ValueError.
fn valid_contextj(label: &[u32], pos: usize) -> Result<bool, ()> {
    const VIRAMA: u8 = 9;
    match label[pos] {
        0x200C => {
            if pos > 0 && combining_class(label[pos - 1])? == VIRAMA {
                return Ok(true);
            }
            let mut ok = false;
            for &c in label[..pos].iter().rev() {
                match joining_type(c) {
                    Some('T') => continue,
                    Some('L' | 'D') => ok = true,
                    _ => {}
                }
                break;
            }
            if !ok {
                return Ok(false);
            }
            let mut ok = false;
            for &c in &label[pos + 1..] {
                match joining_type(c) {
                    Some('T') => continue,
                    Some('R' | 'D') => ok = true,
                    _ => {}
                }
                break;
            }
            Ok(ok)
        }
        0x200D => Ok(pos > 0 && combining_class(label[pos - 1])? == VIRAMA),
        _ => Ok(false),
    }
}

fn valid_contexto(label: &[u32], pos: usize) -> bool {
    let cp = label[pos];
    let len = label.len();
    match cp {
        0xB7 => 0 < pos && pos < len - 1 && label[pos - 1] == 0x6C && label[pos + 1] == 0x6C,
        0x375 => pos < len - 1 && len > 1 && in_ranges(d::SCRIPT_GREEK, label[pos + 1]),
        0x5F3 | 0x5F4 => pos > 0 && in_ranges(d::SCRIPT_HEBREW, label[pos - 1]),
        0x30FB => label.iter().any(|&c| {
            c != 0x30FB
                && (in_ranges(d::SCRIPT_HIRAGANA, c)
                    || in_ranges(d::SCRIPT_KATAKANA, c)
                    || in_ranges(d::SCRIPT_HAN, c))
        }),
        0x660..=0x669 => !label.iter().any(|&c| (0x6F0..=0x6F9).contains(&c)),
        0x6F0..=0x6F9 => !label.iter().any(|&c| (0x660..=0x669).contains(&c)),
        _ => false,
    }
}

fn bidi_error(message: impl Into<String>) -> PyErr {
    idna_error("IDNABidiError", message)
}

/// `check_bidi(label)`.
fn check_bidi(label: &[u32]) -> Result<(), PyErr> {
    if label.len() > MAX_INPUT {
        return Err(error("Label too long"));
    }
    let mut bidi_label = false;
    for (i, &cp) in label.iter().enumerate() {
        let direction = bidirectional_cp(cp);
        if direction.is_empty() {
            return Err(bidi_error(format!(
                "Unknown directionality in label {} at position {}",
                repr_cps(label),
                i + 1
            )));
        }
        if matches!(direction, "R" | "AL" | "AN") {
            bidi_label = true;
        }
    }
    if !bidi_label {
        return Ok(());
    }
    let rtl = match bidirectional_cp(label[0]) {
        "R" | "AL" => true,
        "L" => false,
        _ => {
            return Err(bidi_error(format!(
                "First codepoint in label {} must be directionality L, R or AL",
                repr_cps(label)
            )));
        }
    };
    let mut valid_ending = false;
    let mut number_type: Option<&str> = None;
    for (i, &cp) in label.iter().enumerate() {
        let idx = i + 1;
        let direction = bidirectional_cp(cp);
        if rtl {
            if !matches!(
                direction,
                "R" | "AL" | "AN" | "EN" | "ES" | "CS" | "ET" | "ON" | "BN" | "NSM"
            ) {
                return Err(bidi_error(format!(
                    "Invalid direction for codepoint at position {idx} in a right-to-left label"
                )));
            }
            if matches!(direction, "R" | "AL" | "EN" | "AN") {
                valid_ending = true;
            } else if direction != "NSM" {
                valid_ending = false;
            }
            if matches!(direction, "AN" | "EN") {
                match number_type {
                    None => number_type = Some(direction),
                    Some(t) if t != direction => {
                        return Err(bidi_error(
                            "Can not mix numeral types in a right-to-left label",
                        ));
                    }
                    Some(_) => {}
                }
            }
        } else {
            if !matches!(
                direction,
                "L" | "EN" | "ES" | "CS" | "ET" | "ON" | "BN" | "NSM"
            ) {
                return Err(bidi_error(format!(
                    "Invalid direction for codepoint at position {idx} in a left-to-right label"
                )));
            }
            if matches!(direction, "L" | "EN") {
                valid_ending = true;
            } else if direction != "NSM" {
                valid_ending = false;
            }
        }
    }
    if !valid_ending {
        return Err(bidi_error(
            "Label ends with illegal codepoint directionality",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::testdata::{Mismatches, outcome, s};

    #[test]
    fn encode_and_decode_match_python() {
        let data: Value = crate::testdata::load("idna", include_str!("../tests/data/idna.json"));
        let mut m = Mismatches::new("idna");
        for case in data.as_array().unwrap() {
            let x = s(case, "s");
            let got = json!({
                "s": x,
                "encode": outcome(encode(x), |v| json!(v)),
                "decode": outcome(decode(x), |v| json!(v)),
            });
            m.check(x, &got, case);
        }
        m.finish();
    }
}
