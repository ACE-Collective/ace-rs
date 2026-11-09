//! pyasn1 0.6.5's DER decoder called with no `asn1Spec`, as `saq.x509.is_der_bytes` calls it:
//! `pyasn1.codec.der.decoder.decode(data)`. Only whether it returns or raises matters to ace3,
//! because `is_x509` treats any exception as "not DER", so this keeps no decoded values.
//!
//! What the decoder does without a spec, as ported here:
//!
//! - It decodes one element and ignores whatever follows it.
//! - Tags: short or long form (up to 20 octets). The decoder is picked by class and number, not
//!   by the constructed bit, so a long-form tag 2 is an INTEGER and a constructed INTEGER reaches
//!   the INTEGER decoder, which refuses it. A universal number it has no decoder for (0, 8, 11,
//!   14, 15, 29, 31 and up) is refused. A constructed non-universal element is taken as an
//!   explicit tag around exactly one element; a primitive one is refused.
//! - Lengths: short or long form, up to 8 length octets, non-minimal forms allowed; indefinite
//!   length is refused. Content past the end of the input is an underrun.
//! - BOOLEAN must be one octet, 0x00 or 0xFF (the constructed bit is not checked). INTEGER and
//!   ENUMERATED take any content, empty included. NULL must be empty. OBJECT IDENTIFIER and
//!   RELATIVE-OID must not be empty, no arc may start with 0x80, an arc has at most 20
//!   continuation octets, and the last arc must not be cut short. BIT STRING must not be empty
//!   and its first octet must be at most 7. BIT STRING and OCTET STRING must be primitive.
//! - The character strings (and UTCTime, GeneralizedTime, ObjectDescriptor) must decode in
//!   pyasn1's codec for the type: UTF-8, ASCII, ISO-8859-1, UTF-32-BE or UTF-16-BE. They may be
//!   constructed, from fragments of the same type, each of which must decode on its own.
//! - REAL follows pyasn1's decoder, with Python's `int()` and `float()` for the character forms.
//! - A SEQUENCE or SET with no elements decodes to `None`; that is fine at the top (or inside
//!   explicit tags at the top), but as an element of another SEQUENCE or SET it raises.
//! - Nesting deeper than 100 levels raises.

/// The deepest `_nestingLevel` pyasn1 decodes; level 101 raises.
const MAX_NESTING_DEPTH: u32 = 100;
const MAX_TAG_OCTETS: usize = 20;
const MAX_LENGTH_OCTETS: usize = 8;
const MAX_OID_ARC_CONTINUATION_OCTETS: usize = 20;
/// Python's default `sys.get_int_max_str_digits()`.
const INT_MAX_STR_DIGITS: usize = 4300;

/// Whether `pyasn1.codec.der.decoder.decode(data)` returns without raising.
pub fn is_der_bytes(data: &[u8]) -> bool {
    decode(data, 0, 0, None).is_ok()
}

struct Fail;

/// What a decoded element was, as far as its parent cares.
enum Decoded {
    /// A SEQUENCE or SET with no elements, which pyasn1 returns as `None`.
    Empty,
    Value,
    /// A character string's octets, for a constructed string that joins its fragments.
    Octets(Vec<u8>),
}

#[derive(Clone, Copy)]
enum Codec {
    Utf8,
    Ascii,
    Latin1,
    Utf32Be,
    Utf16Be,
}

fn string_codec(number: u64) -> Option<Codec> {
    Some(match number {
        12 => Codec::Utf8,
        18 | 19 | 22 | 23 | 24 | 26 => Codec::Ascii,
        7 | 20 | 21 | 25 | 27 => Codec::Latin1,
        28 => Codec::Utf32Be,
        30 => Codec::Utf16Be,
        _ => return None,
    })
}

fn decodes(codec: Codec, b: &[u8]) -> bool {
    match codec {
        Codec::Utf8 => std::str::from_utf8(b).is_ok(),
        Codec::Ascii => b.is_ascii(),
        Codec::Latin1 => true,
        Codec::Utf32Be => {
            b.len().is_multiple_of(4)
                && b.as_chunks::<4>()
                    .0
                    .iter()
                    .all(|c| char::from_u32(u32::from_be_bytes(*c)).is_some())
        }
        Codec::Utf16Be => {
            b.len().is_multiple_of(2)
                && char::decode_utf16(b.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)))
                    .all(|r| r.is_ok())
        }
    }
}

/// Decodes the element at `pos`. `fragment_of` is the universal tag number a constructed
/// string's fragment must have (pyasn1 passes the string type as the spec). Returns the element
/// and the position after it.
fn decode(
    d: &[u8],
    mut pos: usize,
    level: u32,
    fragment_of: Option<u64>,
) -> Result<(Decoded, usize), Fail> {
    if level > MAX_NESTING_DEPTH {
        return Err(Fail);
    }
    let first = *d.get(pos).ok_or(Fail)?;
    pos += 1;
    let universal = first & 0xC0 == 0;
    let constructed = first & 0x20 != 0;
    // Tag numbers that do not fit in 64 bits are none of the universal ones pyasn1 knows.
    let mut number = u64::from(first & 0x1F);
    if number == 0x1F {
        number = 0;
        let mut count = 0;
        loop {
            let b = *d.get(pos).ok_or(Fail)?;
            pos += 1;
            count += 1;
            if count > MAX_TAG_OCTETS {
                return Err(Fail);
            }
            number = number
                .checked_mul(128)
                .map_or(u64::MAX, |n| n | u64::from(b & 0x7F));
            if b & 0x80 == 0 {
                break;
            }
        }
    }

    let first_len = *d.get(pos).ok_or(Fail)?;
    pos += 1;
    let length = if first_len < 0x80 {
        usize::from(first_len)
    } else if first_len > 0x80 {
        let size = usize::from(first_len & 0x7F);
        if size > MAX_LENGTH_OCTETS {
            return Err(Fail);
        }
        let octets = d.get(pos..pos + size).ok_or(Fail)?;
        pos += size;
        let mut n: u64 = 0;
        for &o in octets {
            n = (n << 8) | u64::from(o);
        }
        // Longer than the input: the content cannot be read, whatever the decoder.
        usize::try_from(n).map_err(|_| Fail)?
    } else {
        // Indefinite length; the DER decoder does not support it.
        return Err(Fail);
    };
    if length > d.len() - pos {
        return Err(Fail);
    }
    let start = pos;
    let end = pos + length;
    let content = &d[start..end];

    if let Some(want) = fragment_of {
        // Only the string type itself matches the spec. An explicit tag inside a fragment never
        // ends at a matching type, so it fails too.
        if !(universal && number == want) {
            return Err(Fail);
        }
    } else if !universal {
        if !constructed {
            return Err(Fail);
        }
        let (inner, after) = decode(d, start, level + 1, None)?;
        if after != end {
            return Err(Fail);
        }
        return Ok((inner, end));
    }

    let value = match number {
        1 => {
            if length != 1 || !(content[0] == 0 || content[0] == 0xFF) {
                return Err(Fail);
            }
            Decoded::Value
        }
        2 | 10 => {
            if constructed {
                return Err(Fail);
            }
            Decoded::Value
        }
        3 => {
            if length == 0 || constructed || content[0] > 7 {
                return Err(Fail);
            }
            Decoded::Value
        }
        4 => {
            if constructed {
                return Err(Fail);
            }
            Decoded::Value
        }
        5 => {
            if constructed || length != 0 {
                return Err(Fail);
            }
            Decoded::Value
        }
        6 | 13 => {
            if constructed || !oid_ok(content) {
                return Err(Fail);
            }
            Decoded::Value
        }
        9 => {
            if constructed || !real_ok(content) {
                return Err(Fail);
            }
            Decoded::Value
        }
        16 | 17 => {
            if !constructed {
                return Err(Fail);
            }
            let mut count = 0usize;
            while pos < end {
                let (child, after) = decode(d, pos, level + 1, None)?;
                // A `None` element: pyasn1 reads its tagSet (AttributeError) or cannot store it.
                if matches!(child, Decoded::Empty) {
                    return Err(Fail);
                }
                pos = after;
                count += 1;
            }
            if pos != end {
                return Err(Fail);
            }
            if count == 0 {
                Decoded::Empty
            } else {
                Decoded::Value
            }
        }
        n => {
            let codec = string_codec(n).ok_or(Fail)?;
            if !constructed {
                if !decodes(codec, content) {
                    return Err(Fail);
                }
                Decoded::Octets(content.to_vec())
            } else {
                let mut joined = Vec::new();
                while pos < end {
                    let (fragment, after) = decode(d, pos, level + 1, Some(n))?;
                    if let Decoded::Octets(o) = fragment {
                        joined.extend_from_slice(&o);
                    }
                    pos = after;
                }
                if pos != end || !decodes(codec, &joined) {
                    return Err(Fail);
                }
                Decoded::Octets(joined)
            }
        }
    };
    Ok((value, end))
}

fn oid_ok(c: &[u8]) -> bool {
    if c.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < c.len() {
        let sub = c[i];
        i += 1;
        if sub == 0x80 {
            return false;
        }
        if sub > 0x80 {
            let mut next = sub;
            let mut count = 0;
            while next >= 0x80 {
                count += 1;
                if count > MAX_OID_ARC_CONTINUATION_OCTETS || i >= c.len() {
                    return false;
                }
                next = c[i];
                i += 1;
            }
        }
    }
    true
}

fn real_ok(c: &[u8]) -> bool {
    let Some((&fo, mut rest)) = c.split_first() else {
        return true;
    };
    if fo & 0x80 != 0 {
        if rest.is_empty() {
            return false;
        }
        let mut n = usize::from(fo & 0x03) + 1;
        if n == 4 {
            n = usize::from(rest[0]);
            rest = &rest[1..];
        }
        let n = n.min(rest.len());
        let (eo, mantissa) = rest.split_at(n);
        if eo.is_empty() || mantissa.is_empty() {
            return false;
        }
        (fo >> 4) & 0x03 <= 2
    } else if fo & 0x40 != 0 {
        true
    } else {
        if rest.is_empty() {
            return false;
        }
        match fo & 0x03 {
            1 => py_int_ok(rest),
            // Real.prettyIn turns the float into a mantissa with int(), which raises for nan.
            2 | 3 => py_float(rest).is_some_and(|f| !f.is_nan()),
            _ => false,
        }
    }
}

fn py_strip(b: &[u8]) -> &[u8] {
    let ws = |c: &u8| matches!(c, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r');
    let start = b.iter().position(|c| !ws(c)).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !ws(c)).map_or(start, |i| i + 1);
    &b[start..end]
}

/// Digits with single underscores between them, as Python's number parsers allow. Returns the
/// number of digits, or `None` if `b` is not such a run.
fn digit_run(b: &[u8]) -> Option<usize> {
    if b.is_empty() || !b[0].is_ascii_digit() || !b[b.len() - 1].is_ascii_digit() {
        return None;
    }
    let mut digits = 0;
    let mut prev_underscore = false;
    for &c in b {
        if c == b'_' {
            if prev_underscore {
                return None;
            }
            prev_underscore = true;
        } else if c.is_ascii_digit() {
            prev_underscore = false;
            digits += 1;
        } else {
            return None;
        }
    }
    Some(digits)
}

/// Whether Python's `int(b)` (base 10) succeeds.
fn py_int_ok(b: &[u8]) -> bool {
    let s = py_strip(b);
    let s = s
        .strip_prefix(b"+")
        .or_else(|| s.strip_prefix(b"-"))
        .unwrap_or(s);
    digit_run(s).is_some_and(|n| n <= INT_MAX_STR_DIGITS)
}

/// Python's `float(b)`, or `None` where it raises.
fn py_float(b: &[u8]) -> Option<f64> {
    let s = py_strip(b);
    let (neg, body) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let lower = body.to_ascii_lowercase();
    let special = match lower.as_slice() {
        b"inf" | b"infinity" => Some(f64::INFINITY),
        b"nan" => Some(f64::NAN),
        _ => None,
    };
    if let Some(v) = special {
        return Some(if neg { -v } else { v });
    }
    let (mantissa, exponent) = match body.iter().position(|&c| c == b'e' || c == b'E') {
        Some(i) => (&body[..i], Some(&body[i + 1..])),
        None => (body, None),
    };
    let (int_part, frac_part) = match mantissa.iter().position(|&c| c == b'.') {
        Some(i) => (&mantissa[..i], Some(&mantissa[i + 1..])),
        None => (mantissa, None),
    };
    let int_ok = int_part.is_empty() || digit_run(int_part).is_some();
    let frac_ok = match frac_part {
        None => true,
        Some(f) => f.is_empty() || digit_run(f).is_some(),
    };
    let has_digits = !int_part.is_empty() || frac_part.is_some_and(|f| !f.is_empty());
    if !int_ok || !frac_ok || !has_digits {
        return None;
    }
    let mut text: String = mantissa
        .iter()
        .filter(|&&c| c != b'_')
        .map(|&c| char::from(c))
        .collect();
    if let Some(e) = exponent {
        let digits = e
            .strip_prefix(b"+")
            .or_else(|| e.strip_prefix(b"-"))
            .unwrap_or(e);
        digit_run(digits)?;
        text.push('e');
        text.extend(e.iter().filter(|&&c| c != b'_').map(|&c| char::from(c)));
    }
    let v: f64 = text.parse().ok()?;
    Some(if neg { -v } else { v })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_number_parsers() {
        for ok in [&b"1"[..], b" -12 ", b"1_000", b"+0", b"007"] {
            assert!(py_int_ok(ok), "{ok:?}");
        }
        for bad in [
            &b""[..],
            b"1.5",
            b"_1",
            b"1_",
            b"1__0",
            b"1\x00",
            b"- 1",
            b"0x10",
        ] {
            assert!(!py_int_ok(bad), "{bad:?}");
        }
        assert_eq!(py_float(b"1.5"), Some(1.5));
        assert_eq!(py_float(b" .5e1_0 "), Some(0.5e10));
        assert_eq!(py_float(b"-Infinity"), Some(f64::NEG_INFINITY));
        assert_eq!(py_float(b"5."), Some(5.0));
        for bad in [
            &b"."[..],
            b"e5",
            b"1e",
            b"1_.5",
            b"1._5",
            b"0x1p3",
            b"1e+_5",
            b"in f",
        ] {
            assert_eq!(py_float(bad), None, "{bad:?}");
        }
    }
}
