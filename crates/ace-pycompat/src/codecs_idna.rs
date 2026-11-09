//! Python's `idna` codec (`encodings.idna`, IDNA 2003) and the `punycode` codec it uses:
//! `str.encode("idna")` and `bytes.decode("idna")`.
//!
//! Encoding splits on `.` and the three other dots, maps and normalizes each non-ASCII label with
//! nameprep (stringprep tables and NFKC of Unicode 3.2, `tables/stringprep.py`), and punycodes it.
//! Decoding splits bytes on `.` only. Errors are `UnicodeEncodeError` and `UnicodeDecodeError` with
//! Python's positions and reasons.
//!
//! Punycode decoding works on Python's unbounded integers. A huge delta makes a position that
//! doesn't fit a C `ssize_t`, and building the `UnicodeDecodeError` then raises `OverflowError`
//! instead, which is what Python does. Decoded labels are code points, since punycode can decode
//! to a lone surrogate, which nameprep then rejects.

use crate::PyErr;
use crate::pystr::lower;
use crate::repr::{repr_bytes, repr_cps};
use crate::tables::in_ranges;
use crate::tables::stringprep as sp;
use crate::unicodedata::{Form, normalize_cps};

const ACE_PREFIX: &[u8] = b"xn--";

fn is_dot(c: u32) -> bool {
    matches!(c, 0x2E | 0x3002 | 0xFF0E | 0xFF61)
}

fn overflow() -> PyErr {
    PyErr::builtin(
        "OverflowError",
        "Python int too large to convert to C ssize_t",
    )
}

fn ssize(v: i128) -> Result<i64, PyErr> {
    i64::try_from(v).map_err(|_| overflow())
}

/// A `UnicodeError` on its way out: Python's fields, before they're formatted.
#[derive(Debug)]
enum UErr {
    Encode {
        object: Vec<u32>,
        start: i64,
        end: i64,
        reason: String,
    },
    Decode {
        encoding: &'static str,
        object: Vec<u8>,
        start: i64,
        end: i64,
        reason: String,
    },
    /// Anything else, such as `OverflowError`, which nothing here catches.
    Other(PyErr),
}

fn encode_err(object: &[u32], start: i128, end: i128, reason: impl Into<String>) -> UErr {
    match (ssize(start), ssize(end)) {
        (Ok(start), Ok(end)) => UErr::Encode {
            object: object.to_vec(),
            start,
            end,
            reason: reason.into(),
        },
        _ => UErr::Other(overflow()),
    }
}

fn decode_err(
    encoding: &'static str,
    object: &[u8],
    start: i128,
    end: i128,
    reason: impl Into<String>,
) -> UErr {
    match (ssize(start), ssize(end)) {
        (Ok(start), Ok(end)) => UErr::Decode {
            encoding,
            object: object.to_vec(),
            start,
            end,
            reason: reason.into(),
        },
        _ => UErr::Other(overflow()),
    }
}

impl UErr {
    fn into_py(self) -> PyErr {
        match self {
            UErr::Encode {
                object,
                start,
                end,
                reason,
            } => encode_error_message(&object, start, end, &reason),
            UErr::Decode {
                encoding,
                object,
                start,
                end,
                reason,
            } => crate::pystr::unicode_decode_error(encoding, &object, start, end, &reason),
            UErr::Other(e) => e,
        }
    }

    fn span(&self) -> Option<(i64, i64, &str)> {
        match self {
            UErr::Encode {
                start, end, reason, ..
            }
            | UErr::Decode {
                start, end, reason, ..
            } => Some((*start, *end, reason)),
            UErr::Other(_) => None,
        }
    }
}

fn encode_error_message(object: &[u32], start: i64, end: i64, reason: &str) -> PyErr {
    let len = object.len() as i64;
    let message = if (0..len).contains(&start) && (0..=len).contains(&end) && end == start + 1 {
        let c = object[start as usize];
        let shown = if c <= 0xff {
            format!("\\x{c:02x}")
        } else if c <= 0xffff {
            format!("\\u{c:04x}")
        } else {
            format!("\\U{c:08x}")
        };
        format!("'idna' codec can't encode character '{shown}' in position {start}: {reason}")
    } else {
        format!(
            "'idna' codec can't encode characters in position {start}-{}: {reason}",
            end.wrapping_sub(1)
        )
    };
    PyErr::builtin("UnicodeEncodeError", message)
}

/// `stringprep`'s nameprep as `encodings.idna.nameprep` does it.
fn nameprep(label: &[u32]) -> Result<Vec<u32>, UErr> {
    let mut mapped = Vec::with_capacity(label.len());
    for &c in label {
        if in_ranges(sp::B1, c) {
            continue;
        }
        match crate::tables::lookup(sp::B2, c) {
            Some(m) => mapped.extend(m.chars().map(|c| c as u32)),
            None => mapped.push(c),
        }
    }
    let label = normalize_cps(Form::Nfkc, mapped.into_iter(), true);
    for (i, &c) in label.iter().enumerate() {
        if in_ranges(sp::PROHIBITED, c) {
            let i = i as i128;
            return Err(encode_err(
                &label,
                i,
                i + 1,
                format!("Invalid character {}", repr_cps(&[c])),
            ));
        }
    }
    let rand_al: Vec<bool> = label.iter().map(|&c| in_ranges(sp::D1, c)).collect();
    if rand_al.iter().any(|&x| x) {
        for (i, &c) in label.iter().enumerate() {
            if in_ranges(sp::D2, c) {
                let i = i as i128;
                return Err(encode_err(
                    &label,
                    i,
                    i + 1,
                    "Violation of BIDI requirement 2",
                ));
            }
        }
        if !rand_al[0] {
            return Err(encode_err(&label, 0, 1, "Violation of BIDI requirement 3"));
        }
        if !rand_al[rand_al.len() - 1] {
            let n = label.len() as i128;
            return Err(encode_err(
                &label,
                n - 1,
                n,
                "Violation of BIDI requirement 3",
            ));
        }
    }
    Ok(label)
}

fn to_ascii(label: &[u32]) -> Result<Vec<u8>, UErr> {
    if label.iter().all(|&c| c < 0x80) {
        let n = label.len();
        if 0 < n && n < 64 {
            return Ok(label.iter().map(|&c| c as u8).collect());
        }
        if n == 0 {
            return Err(encode_err(label, 0, 1, "label empty"));
        }
        return Err(encode_err(label, 0, n as i128, "label too long"));
    }
    let label = nameprep(label)?;
    if label.iter().all(|&c| c < 0x80) {
        let n = label.len();
        if 0 < n && n < 64 {
            return Ok(label.iter().map(|&c| c as u8).collect());
        }
        if n == 0 {
            return Err(encode_err(&label, 0, 1, "label empty"));
        }
        return Err(encode_err(&label, 0, n as i128, "label too long"));
    }
    if lower_cps(&label).starts_with(&[0x78, 0x6E, 0x2D, 0x2D]) {
        return Err(encode_err(&label, 0, 4, "Label starts with ACE prefix"));
    }
    let mut out = ACE_PREFIX.to_vec();
    out.extend(punycode_encode(&label));
    if out.len() < 64 {
        return Ok(out);
    }
    Err(encode_err(&label, 0, label.len() as i128, "label too long"))
}

/// `str.lower()` over code points; a lone surrogate stays as it is.
fn lower_cps(cps: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(cps.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut Vec<u32>| {
        out.extend(lower(run).chars().map(|c| c as u32));
        run.clear();
    };
    for &cp in cps {
        match char::from_u32(cp) {
            Some(c) => run.push(c),
            None => {
                flush(&mut run, &mut out);
                out.push(cp);
            }
        }
    }
    flush(&mut run, &mut out);
    out
}

/// `input.encode("idna")`.
pub fn encode(input: &str) -> Result<String, PyErr> {
    if input.is_empty() {
        return Ok(String::new());
    }
    let cps: Vec<u32> = input.chars().map(|c| c as u32).collect();
    if input.is_ascii() {
        let labels: Vec<&str> = input.split('.').collect();
        let mut offset = 0_i128;
        for label in &labels[..labels.len() - 1] {
            if label.is_empty() {
                return Err(encode_err(&cps, offset, offset + 1, "label empty").into_py());
            }
            offset += label.len() as i128 + 1;
        }
        let mut offset = 0_i128;
        for label in &labels {
            if label.len() >= 64 {
                return Err(encode_err(
                    &cps,
                    offset,
                    offset + label.len() as i128,
                    "label too long",
                )
                .into_py());
            }
            offset += label.len() as i128 + 1;
        }
        return Ok(input.to_owned());
    }
    let mut labels: Vec<&[u32]> = cps.split(|&c| is_dot(c)).collect();
    let trailing_dot = labels.last().is_some_and(|l| l.is_empty());
    if trailing_dot {
        labels.pop();
    }
    let mut result: Vec<u8> = Vec::new();
    let mut offset = 0_i128;
    for label in labels {
        if !result.is_empty() {
            result.push(b'.');
        }
        match to_ascii(label) {
            Ok(b) => result.extend(b),
            Err(e) => {
                return Err(match e.span() {
                    Some((start, end, reason)) => encode_err(
                        &cps,
                        offset + start as i128,
                        offset + end as i128,
                        reason.to_owned(),
                    )
                    .into_py(),
                    None => e.into_py(),
                });
            }
        }
        offset += label.len() as i128 + 1;
    }
    if trailing_dot {
        result.push(b'.');
    }
    Ok(result.into_iter().map(char::from).collect())
}

fn to_unicode(label: &[u8]) -> Result<Vec<u32>, UErr> {
    if label.len() > 1024 {
        return Err(decode_err(
            "idna",
            label,
            0,
            label.len() as i128,
            "label way too long",
        ));
    }
    if !label.to_ascii_lowercase().starts_with(ACE_PREFIX) {
        return match label.iter().position(|b| !b.is_ascii()) {
            None => Ok(label.iter().map(|&b| u32::from(b)).collect()),
            Some(i) => Err(decode_err(
                "ascii",
                label,
                i as i128,
                i as i128 + 1,
                "ordinal not in range(128)",
            )),
        };
    }
    let label1 = &label[ACE_PREFIX.len()..];
    let result = match punycode_decode(label1) {
        Ok(r) => r,
        Err(UErr::Decode {
            start, end, reason, ..
        }) => {
            return Err(decode_err(
                "idna",
                label,
                4 + start as i128,
                4 + end as i128,
                reason,
            ));
        }
        Err(e) => return Err(e),
    };
    let label2 = to_ascii(&result)?;
    let lowered = label.to_ascii_lowercase();
    if lowered != label2 {
        return Err(decode_err(
            "idna",
            label,
            0,
            label.len() as i128,
            format!(
                "IDNA does not round-trip, '{}' != '{}'",
                repr_bytes(label),
                repr_bytes(&label2)
            ),
        ));
    }
    Ok(result)
}

/// `input.decode("idna")`.
pub fn decode(input: &[u8]) -> Result<String, PyErr> {
    if input.is_empty() {
        return Ok(String::new());
    }
    let lowered = input.to_ascii_lowercase();
    if !lowered.windows(4).any(|w| w == ACE_PREFIX) && input.is_ascii() {
        return Ok(input.iter().map(|&b| char::from(b)).collect());
    }
    let mut labels: Vec<&[u8]> = input.split(|&b| b == b'.').collect();
    let trailing_dot = labels.last().is_some_and(|l| l.is_empty());
    if trailing_dot {
        labels.pop();
    }
    let mut result: Vec<String> = Vec::with_capacity(labels.len());
    let mut offset = 0_i128;
    for label in labels {
        match to_unicode(label) {
            Ok(u) => result.push(u.into_iter().filter_map(char::from_u32).collect()),
            Err(e) => {
                return Err(match e.span() {
                    Some((start, end, reason)) => decode_err(
                        "idna",
                        input,
                        offset + start as i128,
                        offset + end as i128,
                        reason.to_owned(),
                    )
                    .into_py(),
                    None => e.into_py(),
                });
            }
        }
        offset += label.len() as i128 + 1;
    }
    let mut out = result.join(".");
    if trailing_dot {
        out.push('.');
    }
    Ok(out)
}

const DIGITS: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";

fn t(j: u128, bias: u128) -> u128 {
    let res = 36 * (j + 1) as i128 - bias as i128;
    res.clamp(1, 26) as u128
}

fn adapt(delta: u128, first: bool, numchars: u128) -> u128 {
    let mut delta = if first { delta / 700 } else { delta / 2 };
    delta += delta / numchars;
    let mut divisions = 0;
    while delta > 455 {
        delta /= 35;
        divisions += 36;
    }
    divisions + (36 * delta / (delta + 38))
}

/// `text.encode("punycode")`.
pub fn punycode_encode_str(text: &str) -> Vec<u8> {
    punycode_encode(&text.chars().map(|c| c as u32).collect::<Vec<_>>())
}

fn punycode_encode(text: &[u32]) -> Vec<u8> {
    let base: Vec<u8> = text
        .iter()
        .filter(|&&c| c < 128)
        .map(|&c| c as u8)
        .collect();
    let mut extended: Vec<u32> = text.iter().copied().filter(|&c| c >= 128).collect();
    extended.sort_unstable();
    extended.dedup();
    // insertion_unsort
    let mut deltas: Vec<u128> = Vec::new();
    let mut oldchar: u128 = 0x80;
    let mut oldindex: i128 = -1;
    for &c in &extended {
        let char = u128::from(c);
        let curlen = text.iter().filter(|&&x| u128::from(x) < char).count() as u128;
        let mut delta = (curlen + 1) * (char - oldchar);
        // selective_find, walking the whole string once.
        let mut index: i128 = -1;
        for &x in text {
            if x == c {
                index += 1;
                delta = (delta as i128 + index - oldindex) as u128;
                deltas.push(delta - 1);
                oldindex = index;
                delta = 0;
            } else if x < c {
                index += 1;
            }
        }
        oldchar = char;
    }
    // generate_integers
    let mut out = Vec::new();
    let mut bias = 72;
    for (points, &delta) in deltas.iter().enumerate() {
        let mut n = delta;
        let mut j = 0;
        loop {
            let tt = t(j, bias);
            if n < tt {
                out.push(DIGITS[n as usize]);
                break;
            }
            out.push(DIGITS[(tt + (n - tt) % (36 - tt)) as usize]);
            n = (n - tt) / (36 - tt);
            j += 1;
        }
        bias = adapt(delta, points == 0, base.len() as u128 + points as u128 + 1);
    }
    if base.is_empty() {
        out
    } else {
        let mut r = base;
        r.push(b'-');
        r.extend(out);
        r
    }
}

/// `text.decode("punycode")` with errors="strict", as code points: `UnicodeDecodeError`, or
/// `OverflowError` when a position doesn't fit a `ssize_t`.
pub(crate) fn punycode_decode_py(text: &[u8]) -> Result<Vec<u32>, PyErr> {
    punycode_decode(text).map_err(UErr::into_py)
}

/// `punycode_encode` over code points.
pub(crate) fn punycode_encode_cps(text: &[u32]) -> Vec<u8> {
    punycode_encode(text)
}

/// `text.decode("punycode")` with errors="strict", as code points.
fn punycode_decode(text: &[u8]) -> Result<Vec<u32>, UErr> {
    let pos = text.iter().rposition(|&b| b == b'-');
    let (base, extended): (Vec<u32>, Vec<u8>) = match pos {
        None => (Vec::new(), text.to_ascii_uppercase()),
        Some(p) => {
            if let Some(i) = text[..p].iter().position(|b| !b.is_ascii()) {
                return Err(decode_err(
                    "ascii",
                    text,
                    i as i128,
                    i as i128 + 1,
                    "ordinal not in range(128)",
                ));
            }
            (
                text[..p].iter().map(|&b| u32::from(b)).collect(),
                text[p + 1..].to_ascii_uppercase(),
            )
        }
    };
    match insertion_sort(base, &extended) {
        Ok(r) => Ok(r),
        Err(UErr::Decode {
            start, end, reason, ..
        }) => {
            let offset = pos.map_or(0, |p| p as i128 + 1);
            Err(decode_err(
                "punycode",
                text,
                offset + start as i128,
                offset + end as i128,
                reason,
            ))
        }
        Err(e) => Err(e),
    }
}

/// Unbounded integers saturate here: any value this large fails the U+10FFFF check, and its
/// position can't be a `ssize_t`, so Python raises `OverflowError` for it, as this does.
fn insertion_sort(mut base: Vec<u32>, extended: &[u8]) -> Result<Vec<u32>, UErr> {
    let mut char: u128 = 0x80;
    let mut pos: u128 = 0; // Python's pos + 1, which starts at -1.
    let mut bias: u128 = 72;
    let mut extpos = 0;
    while extpos < extended.len() {
        // decode_generalized_number
        let mut result: u128 = 0;
        let mut w: u128 = 1;
        let mut j: u128 = 0;
        let mut newpos = extpos;
        let delta = loop {
            let Some(&c) = extended.get(newpos) else {
                let p = newpos as i128;
                return Err(decode_err(
                    "punycode",
                    extended,
                    p,
                    p + 1,
                    "incomplete punycode string",
                ));
            };
            newpos += 1;
            let digit = match c {
                b'A'..=b'Z' => u128::from(c - b'A'),
                b'0'..=b'9' => u128::from(c - 22),
                _ => {
                    let p = newpos as i128;
                    return Err(decode_err(
                        "punycode",
                        extended,
                        p - 1,
                        p,
                        format!("Invalid extended code point '{c}'"),
                    ));
                }
            };
            let tt = t(j, bias);
            result = result.saturating_add(digit.saturating_mul(w));
            if digit < tt {
                break result;
            }
            w = w.saturating_mul(36 - tt);
            j += 1;
        };
        // Python's `pos += delta + 1`; `pos` here is Python's plus one.
        let new_pos = pos.saturating_add(delta);
        let len = base.len() as u128 + 1;
        char = char.saturating_add(new_pos / len);
        if char > 0x10FFFF {
            let start = i128::try_from(new_pos).ok().map(|p| p - 1);
            return Err(match start {
                Some(s) => decode_err(
                    "punycode",
                    extended,
                    s,
                    s + 1,
                    format!("Invalid character U+{char:x}"),
                ),
                None => UErr::Other(overflow()),
            });
        }
        let at = (new_pos % len) as usize;
        base.insert(at, char as u32);
        bias = adapt(delta, extpos == 0, base.len() as u128);
        extpos = newpos;
        pos = at as u128 + 1;
    }
    Ok(base)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::testdata::{Mismatches, hex, outcome, s};

    fn data() -> Value {
        crate::testdata::load(
            "codecs_idna",
            include_str!("../tests/data/codecs_idna.json"),
        )
    }

    #[test]
    fn encode_matches_python() {
        let data = data();
        let mut m = Mismatches::new("idna codec encode");
        for case in data["encode"].as_array().unwrap() {
            let x = s(case, "s");
            m.check(
                x,
                &json!({"s": x, "out": outcome(encode(x), |v| json!(v))}),
                case,
            );
        }
        m.finish();
        let mut m = Mismatches::new("punycode encode");
        for case in data["punycode"].as_array().unwrap() {
            let x = s(case, "s");
            let out = String::from_utf8(punycode_encode_str(x)).unwrap();
            m.check(x, &json!({"s": x, "out": out}), case);
        }
        m.finish();
    }

    #[test]
    fn decode_matches_python() {
        let data = data();
        let mut m = Mismatches::new("idna codec decode");
        for case in data["decode"].as_array().unwrap() {
            let b = hex(case, "b");
            m.check(
                String::from_utf8_lossy(&b),
                &json!({"b": s(case, "b"), "out": outcome(decode(&b), |v| json!(v))}),
                case,
            );
        }
        m.finish();
    }
}
