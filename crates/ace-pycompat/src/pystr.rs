//! Python `str` semantics on `&str`, and `bytes.decode("utf-8")` with its error handlers.
//!
//! The character predicates are `str.isspace` and friends on one character. `re`'s `\s` for a str
//! pattern is `is_space`, `\d` is `is_decimal` and `\w` is `is_word`. `isspace` holds for
//! `\x1c`-`\x1f` and `\x85`, which Rust's `char::is_whitespace` doesn't; `lower` and `upper` apply
//! Python's full case mappings (`"\u{130}".lower()` is two characters, `"\u{df}".upper()` is `"SS"`) and its
//! final sigma rule. The tables come from Python 3.14 (`tables/unicode.py`).

use std::borrow::Cow;

use crate::PyErr;
use crate::tables::unicode as t;
use crate::tables::{in_ranges, lookup};

/// `c.isspace()`.
#[inline]
pub fn is_space(c: char) -> bool {
    match c {
        ' ' | '\t'..='\r' | '\x1c'..='\x1f' => true,
        _ if c.is_ascii() => false,
        _ => in_ranges(t::SPACE, c as u32),
    }
}

/// `c.isalpha()`.
#[inline]
pub fn is_alpha(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_alphabetic()
    } else {
        in_ranges(t::ALPHA, c as u32)
    }
}

/// `c.isalnum()`.
#[inline]
pub fn is_alnum(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_alphanumeric()
    } else {
        in_ranges(t::ALNUM, c as u32)
    }
}

/// `c.isdecimal()`, which is `re`'s `\d`.
#[inline]
pub fn is_decimal(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_digit()
    } else {
        in_ranges(t::DECIMAL, c as u32)
    }
}

/// `c.isdigit()`.
#[inline]
pub fn is_digit(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_digit()
    } else {
        in_ranges(t::DIGIT, c as u32)
    }
}

/// `re`'s `\w` for a str pattern: `c.isalnum() or c == "_"`.
#[inline]
pub fn is_word(c: char) -> bool {
    c == '_' || is_alnum(c)
}

/// `c.isprintable()`.
#[inline]
pub fn is_printable(c: char) -> bool {
    if c.is_ascii() {
        (' '..='~').contains(&c)
    } else {
        in_ranges(t::PRINTABLE, c as u32)
    }
}

/// `s.isascii()`.
#[inline]
pub fn is_ascii(s: &str) -> bool {
    s.is_ascii()
}

/// `s.isdigit()`: true when `s` isn't empty and every character is a digit.
pub fn str_is_digit(s: &str) -> bool {
    !s.is_empty() && s.chars().all(is_digit)
}

/// `s.strip()`.
pub fn strip(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// `s.lstrip()`.
pub fn lstrip(s: &str) -> &str {
    s.trim_start_matches(is_space)
}

/// `s.rstrip()`.
pub fn rstrip(s: &str) -> &str {
    s.trim_end_matches(is_space)
}

/// `s.strip(chars)`.
pub fn strip_chars<'a>(s: &'a str, chars: &str) -> &'a str {
    s.trim_matches(|c| chars.contains(c))
}

/// `s.lstrip(chars)`.
pub fn lstrip_chars<'a>(s: &'a str, chars: &str) -> &'a str {
    s.trim_start_matches(|c| chars.contains(c))
}

/// `s.rstrip(chars)`.
pub fn rstrip_chars<'a>(s: &'a str, chars: &str) -> &'a str {
    s.trim_end_matches(|c| chars.contains(c))
}

/// Whether `c` ends a line for `str.splitlines`.
#[inline]
pub fn is_line_boundary(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r'
            | '\x0b'
            | '\x0c'
            | '\x1c'
            | '\x1d'
            | '\x1e'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

/// `s.splitlines()`.
pub fn splitlines(s: &str) -> Vec<&str> {
    splitlines_inner(s, false)
}

/// `s.splitlines(keepends=True)`.
pub fn splitlines_keepends(s: &str) -> Vec<&str> {
    splitlines_inner(s, true)
}

fn splitlines_inner(s: &str, keepends: bool) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut start = 0;
    let mut iter = s.char_indices().peekable();
    while let Some((i, c)) = iter.next() {
        if !is_line_boundary(c) {
            continue;
        }
        let mut end = i + c.len_utf8();
        if c == '\r' && bytes.get(end) == Some(&b'\n') {
            iter.next();
            end += 1;
        }
        out.push(if keepends {
            &s[start..end]
        } else {
            &s[start..i]
        });
        start = end;
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// `s.split(sep)` with a non-empty separator.
pub fn split<'a>(s: &'a str, sep: &str) -> Vec<&'a str> {
    s.split(sep).collect()
}

/// `s.lower()`.
pub fn lower(s: &str) -> Cow<'_, str> {
    if s.is_ascii() {
        if s.bytes().any(|b| b.is_ascii_uppercase()) {
            return Cow::Owned(s.to_ascii_lowercase());
        }
        return Cow::Borrowed(s);
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    for (i, &c) in chars.iter().enumerate() {
        if c == '\u{3a3}' {
            out.push(if final_sigma(&chars, i) {
                '\u{3c2}'
            } else {
                '\u{3c3}'
            });
        } else {
            push_lower(&mut out, c);
        }
    }
    Cow::Owned(out)
}

/// `c.lower()` for a character on its own, appended to `out`.
#[inline]
pub fn push_lower(out: &mut String, c: char) {
    if c.is_ascii() {
        out.push(c.to_ascii_lowercase());
    } else if let Some(m) = lookup(t::LOWER, c as u32) {
        out.push_str(m);
    } else {
        out.push(c);
    }
}

fn final_sigma(chars: &[char], i: usize) -> bool {
    // CPython's handle_capital_sigma.
    let mut j = i;
    let mut before = None;
    while j > 0 {
        j -= 1;
        let c = chars[j] as u32;
        if !in_ranges(t::CASE_IGNORABLE, c) {
            before = Some(c);
            break;
        }
    }
    match before {
        Some(c) if in_ranges(t::CASED, c) => {}
        _ => return false,
    }
    for &c in &chars[i + 1..] {
        let c = c as u32;
        if !in_ranges(t::CASE_IGNORABLE, c) {
            return !in_ranges(t::CASED, c);
        }
    }
    true
}

/// `s.upper()`.
pub fn upper(s: &str) -> Cow<'_, str> {
    if s.is_ascii() {
        if s.bytes().any(|b| b.is_ascii_lowercase()) {
            return Cow::Owned(s.to_ascii_uppercase());
        }
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() {
            out.push(c.to_ascii_uppercase());
        } else if let Some(m) = lookup(t::UPPER, c as u32) {
            out.push_str(m);
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// `s.encode("ascii", errors="ignore").decode()`: `s` without its non-ASCII characters.
pub fn ascii_ignore(s: &str) -> Cow<'_, str> {
    if s.is_ascii() {
        Cow::Borrowed(s)
    } else {
        Cow::Owned(s.chars().filter(char::is_ascii).collect())
    }
}

/// `b.decode("utf-8", errors="ignore")`.
pub fn decode_utf8_ignore(b: &[u8]) -> Cow<'_, str> {
    decode_utf8_with(b, "")
}

/// `b.decode("utf-8", errors="replace")`: each maximal invalid subsequence becomes one U+FFFD.
pub fn decode_utf8_replace(b: &[u8]) -> Cow<'_, str> {
    decode_utf8_with(b, "\u{fffd}")
}

fn decode_utf8_with<'a>(b: &'a [u8], replacement: &str) -> Cow<'a, str> {
    if let Ok(s) = std::str::from_utf8(b) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(b.len());
    for chunk in b.utf8_chunks() {
        out.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            out.push_str(replacement);
        }
    }
    Cow::Owned(out)
}

/// `b.decode("utf-8")`, which raises `UnicodeDecodeError` at the first invalid sequence.
pub fn decode_utf8_strict(b: &[u8]) -> Result<&str, PyErr> {
    std::str::from_utf8(b).map_err(|e| {
        let start = e.valid_up_to();
        let (end, reason) = match e.error_len() {
            None => (b.len(), "unexpected end of data"),
            Some(n) => {
                let first = b[start];
                let reason = if (0x80..=0xc1).contains(&first) || first >= 0xf5 {
                    "invalid start byte"
                } else {
                    "invalid continuation byte"
                };
                (start + n, reason)
            }
        };
        unicode_decode_error("utf-8", b, start as i64, end as i64, reason)
    })
}

/// `b.decode("ascii")`, which raises `UnicodeDecodeError` at the first byte over 127.
pub fn decode_ascii(b: &[u8]) -> Result<&str, PyErr> {
    match b.iter().position(|c| !c.is_ascii()) {
        None => Ok(std::str::from_utf8(b).unwrap_or_default()),
        Some(i) => Err(unicode_decode_error(
            "ascii",
            b,
            i as i64,
            i as i64 + 1,
            "ordinal not in range(128)",
        )),
    }
}

/// `UnicodeDecodeError(encoding, object, start, end, reason)`, with the message Python gives it.
pub fn unicode_decode_error(
    encoding: &str,
    object: &[u8],
    start: i64,
    end: i64,
    reason: &str,
) -> PyErr {
    let len = object.len() as i64;
    let message = if (0..len).contains(&start) && (0..=len).contains(&end) && end == start + 1 {
        format!(
            "'{encoding}' codec can't decode byte 0x{:02x} in position {start}: {reason}",
            object[start as usize]
        )
    } else {
        format!(
            "'{encoding}' codec can't decode bytes in position {start}-{}: {reason}",
            end.wrapping_sub(1)
        )
    };
    PyErr::builtin("UnicodeDecodeError", message)
}

/// `UnicodeEncodeError(encoding, object, start, end, reason)`, with the message Python gives it.
/// `start` and `end` count characters.
pub fn unicode_encode_error(
    encoding: &str,
    object: &str,
    start: i64,
    end: i64,
    reason: &str,
) -> PyErr {
    let len = object.chars().count() as i64;
    let message = if (0..len).contains(&start) && (0..=len).contains(&end) && end == start + 1 {
        let c = object.chars().nth(start as usize).map_or(0, |c| c as u32);
        let shown = if c <= 0xff {
            format!("\\x{c:02x}")
        } else if c <= 0xffff {
            format!("\\u{c:04x}")
        } else {
            format!("\\U{c:08x}")
        };
        format!("'{encoding}' codec can't encode character '{shown}' in position {start}: {reason}")
    } else {
        format!(
            "'{encoding}' codec can't encode characters in position {start}-{}: {reason}",
            end.wrapping_sub(1)
        )
    };
    PyErr::builtin("UnicodeEncodeError", message)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::repr::{repr, repr_bytes};
    use crate::testdata::{Mismatches, all_chars, digest, hex, outcome, s};
    use crate::unicodedata::{self as ud, Form, ucd_3_2_0};

    fn data() -> Value {
        crate::testdata::load("pystr", include_str!("../tests/data/pystr.json"))
    }

    fn one(c: char) -> String {
        c.to_string()
    }

    #[test]
    fn every_code_point_matches_python() {
        let data = data();
        let want = &data["digests"];
        let mut bad = Vec::new();
        let mut check = |name: &str, got: String| {
            if want[name].as_str() != Some(got.as_str()) {
                bad.push(name.to_owned());
            }
        };
        check("category", digest(all_chars().map(ud::category)));
        check("bidirectional", digest(all_chars().map(ud::bidirectional)));
        check(
            "combining",
            digest(all_chars().map(|c| ud::combining(c).to_string())),
        );
        check(
            "has_name",
            digest(all_chars().map(|c| if ud::has_name(c) { "1" } else { "0" })),
        );
        check(
            "lower",
            digest(all_chars().map(|c| lower(&one(c)).into_owned())),
        );
        check(
            "upper",
            digest(all_chars().map(|c| upper(&one(c)).into_owned())),
        );
        check(
            "predicates",
            digest(all_chars().map(|c| {
                [
                    is_space,
                    is_alpha,
                    is_alnum,
                    is_decimal,
                    is_digit,
                    is_printable,
                ]
                .iter()
                .map(|f| if f(c) { '1' } else { '0' })
                .collect::<String>()
            })),
        );
        check("repr", digest(all_chars().map(|c| repr(&one(c)))));
        check(
            "nfkc_maps_to_other_ascii",
            digest(all_chars().map(|c| {
                if ud::nfkc_maps_to_other_ascii(c) {
                    "1"
                } else {
                    "0"
                }
            })),
        );
        let forms = [
            ("NFC", Form::Nfc),
            ("NFKC", Form::Nfkc),
            ("NFD", Form::Nfd),
            ("NFKD", Form::Nfkd),
        ];
        for (name, form) in forms {
            check(
                name,
                digest(all_chars().map(|c| ud::normalize(form, &one(c)).into_owned())),
            );
            check(
                &format!("3.2 {name}"),
                digest(all_chars().map(|c| ucd_3_2_0::normalize(form, &one(c)).into_owned())),
            );
        }
        check(
            "sigma",
            digest(all_chars().map(|c| {
                format!(
                    "{}{}{}",
                    lower(&format!("A{c}\u{3a3}")),
                    lower(&format!("A\u{3a3}{c}")),
                    lower(&format!("{c}\u{3a3}x"))
                )
            })),
        );
        let seqs: Vec<&str> = data["sequences"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(seqs.len() > 5_000);
        for (name, form) in forms {
            check(
                &format!("sequences {name}"),
                digest(seqs.iter().map(|s| ud::normalize(form, s).into_owned())),
            );
            check(
                &format!("sequences 3.2 {name}"),
                digest(
                    seqs.iter()
                        .map(|s| ucd_3_2_0::normalize(form, s).into_owned()),
                ),
            );
        }
        assert!(bad.is_empty(), "differ from Python: {bad:?}");
    }

    #[test]
    fn strings_match_python() {
        let data = data();
        let mut m = Mismatches::new("pystr strings");
        for case in data["strings"].as_array().unwrap() {
            let x = s(case, "s");
            let got = json!({
                "s": x,
                "lower": lower(x), "upper": upper(x),
                "strip": strip(x), "lstrip": lstrip(x), "rstrip": rstrip(x),
                "strip_chars": strip_chars(x, " .%a\u{e9}"),
                "splitlines": splitlines(x), "splitlines_keepends": splitlines_keepends(x),
                "repr": repr(x),
                "nfc": ud::nfc(x), "nfkc": ud::nfkc(x), "nfkc32": ucd_3_2_0::nfkc(x),
            });
            m.check(x, &got, case);
        }
        m.finish();
    }

    #[test]
    fn bytes_match_python() {
        let data = data();
        let mut m = Mismatches::new("utf-8 decoding");
        for case in data["bytes"].as_array().unwrap() {
            let b = hex(case, "b");
            let got = json!({
                "b": s(case, "b"),
                "ignore": decode_utf8_ignore(&b),
                "replace": decode_utf8_replace(&b),
                "strict": outcome(decode_utf8_strict(&b), |s| json!(s)),
                "repr": repr_bytes(&b),
            });
            m.check(&b, &got, case);
        }
        m.finish();
    }
}
