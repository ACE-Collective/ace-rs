//! `urlfinderlib/helpers.py`.

use std::borrow::Cow;

use crate::py::{self, PyResult};

/// `build_url`.
pub fn build_url(scheme: &str, netloc: &str, path: &str) -> String {
    let mut url = String::with_capacity(scheme.len() + 3 + netloc.len() + path.len());
    url.push_str(scheme);
    url.push_str("://");
    url.push_str(netloc);
    url.push_str(path);
    url
}

/// `fix_possible_url`.
pub fn fix_possible_url(value: &str, domain_as_url: bool) -> String {
    let value = fix_possible_value(value);
    if py::validators_email(&value) {
        value
    } else {
        prepend_missing_scheme(&value, domain_as_url)
    }
}

/// `fix_possible_value`. Each step copies the text only when it changes it, which matters on
/// the long tokens of a hostile file.
pub fn fix_possible_value(value: &str) -> String {
    let value = py::strip(value);
    let value = remove_hidden_unicode_characters(value);
    let value = fix_slashes(&value);
    let value = fix_scheme(&value);
    let value = remove_mailto_if_not_email_address(&value);
    let value = remove_null_characters(&value);
    let value = remove_surrounding_quotes(&value);
    py::rstrip_chars(value, ",;!?").to_owned()
}

/// `fix_scheme`. The start of the split decides; the path is split out only when it's needed.
pub fn fix_scheme(value: &str) -> Cow<'_, str> {
    let Ok(head) = ace_pycompat::parse::urlsplit_head(value) else {
        return Cow::Borrowed("");
    };
    let no_netloc = head.netloc.as_deref().is_none_or(str::is_empty);
    if !head.scheme.is_empty() && no_netloc && !head.path_is_empty {
        let Ok(split) = py::urlsplit(value) else {
            return Cow::Borrowed("");
        };
        return Cow::Owned(format!(
            "{}://{}",
            split.scheme,
            split.path.trim_start_matches('/')
        ));
    }
    Cow::Borrowed(value)
}

/// `fix_slashes`.
pub fn fix_slashes(value: &str) -> Cow<'_, str> {
    let value = if value.contains('\\') {
        Cow::Owned(value.replace('\\', "/"))
    } else {
        Cow::Borrowed(value)
    };
    if !value.contains("://") && value.contains(":/") {
        return Cow::Owned(value.replace(":/", "://"));
    }
    value
}

/// `get_ascii_url`.
pub fn get_ascii_url(url: &str) -> String {
    url.chars().filter(char::is_ascii).collect()
}

/// `decode_base64_ascii`.
pub fn decode_base64_ascii(value: &str) -> String {
    let padded = format!("{value}===");
    for decoder in [py::b64decode, py::urlsafe_b64decode] {
        if let Ok(decoded) = decoder(&padded).and_then(py::decode_ascii) {
            return py::strip(&decoded).to_owned();
        }
    }
    String::new()
}

/// `is_base64_ascii`.
pub fn is_base64_ascii(value: &str) -> bool {
    py::b64decode(&format!("{value}==="))
        .and_then(py::decode_ascii)
        .is_ok()
}

/// `might_be_html`.
pub fn might_be_html(value: &[u8]) -> bool {
    b"<>=:/".iter().all(|c| memchr::memchr(*c, value).is_some())
}

/// `prepend_missing_scheme`.
pub fn prepend_missing_scheme(value: &str, domain_as_url: bool) -> String {
    let value = value.trim_start_matches([':', '/']);
    if is_cidr_notation(value) {
        return value.to_owned();
    }
    let Ok(split) = ace_pycompat::parse::urlsplit_head(value) else {
        return value.to_owned();
    };
    let wanted = if domain_as_url {
        split.scheme.is_empty() && value.contains('.')
    } else {
        split.scheme.is_empty() && value.contains('/')
    };
    if wanted {
        format!("https://{value}")
    } else {
        value.to_owned()
    }
}

/// `_is_cidr_notation`: `^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$`, where `\d` is any
/// decimal digit and `$` may stand before a final newline, then the address checked by
/// ipaddress and the prefix by int().
fn is_cidr_notation(value: &str) -> bool {
    let body = value.strip_suffix('\n').unwrap_or(value);
    let Some((address, prefix)) = body.split_once('/') else {
        return false;
    };
    let digits = |s: &str, max: usize| {
        let n = s.chars().count();
        (1..=max).contains(&n) && s.chars().all(ace_pycompat::pystr::is_decimal)
    };
    let octets: Vec<&str> = address.split('.').collect();
    if octets.len() != 4 || !octets.iter().all(|o| digits(o, 3)) || !digits(prefix, 2) {
        return false;
    }
    if !py::is_ip_address(address) {
        return false;
    }
    // int() reads any decimal digits
    let value: u32 = prefix.chars().map(decimal_value).fold(0, |v, d| v * 10 + d);
    value <= 32
}

/// A decimal digit's value, as int() reads it: its place in its run of ten.
fn decimal_value(c: char) -> u32 {
    if let Some(d) = c.to_digit(10) {
        return d;
    }
    let mut first = u32::from(c);
    while first > 0 && char::from_u32(first - 1).is_some_and(ace_pycompat::pystr::is_decimal) {
        first -= 1;
    }
    (u32::from(c) - first) % 10
}

/// `unescape_ascii`: `\u00XX`, `\xXX` and an unescaped `\/`.
pub fn unescape_ascii(blob: &[u8]) -> Vec<u8> {
    let Some(first) = memchr::memchr(b'\\', blob) else {
        return blob.to_vec();
    };
    let mut out = Vec::with_capacity(blob.len());
    out.extend_from_slice(&blob[..first]);
    let mut i = first;
    while i < blob.len() {
        if blob[i] != b'\\' {
            let next = memchr::memchr(b'\\', &blob[i..]).map_or(blob.len(), |n| i + n);
            out.extend_from_slice(&blob[i..next]);
            i = next;
            continue;
        }
        let rest = &blob[i + 1..];
        let hex = if rest.starts_with(b"u00") && rest.len() >= 5 {
            Some((&rest[3..5], 6))
        } else if rest.first() == Some(&b'x') && rest.len() >= 3 {
            Some((&rest[1..3], 4))
        } else {
            None
        };
        if let Some((digits, len)) = hex
            && digits.iter().all(u8::is_ascii_hexdigit)
        {
            let value =
                u8::from_str_radix(std::str::from_utf8(digits).unwrap_or("0"), 16).unwrap_or(0);
            if value.is_ascii_graphic() {
                out.push(value);
            } else {
                out.extend_from_slice(&blob[i..i + len]);
            }
            i += len;
            continue;
        }
        if rest.first() == Some(&b'/') {
            if i > 0 && blob[i - 1] == b'\\' {
                out.extend_from_slice(b"\\/");
            } else {
                out.push(b'/');
            }
            i += 2;
            continue;
        }
        out.push(b'\\');
        i += 1;
    }
    out
}

const HIDDEN_CHARACTERS: [char; 9] = [
    '\u{200c}', '\u{200d}', '\u{200e}', '\u{ad}', '\u{2060}', '\u{feff}', '\u{200b}', '\u{2061}',
    '\u{115f}',
];

/// `remove_hidden_unicode_characters`.
pub fn remove_hidden_unicode_characters(value: &str) -> Cow<'_, str> {
    if value.is_ascii() || !value.contains(HIDDEN_CHARACTERS) {
        return Cow::Borrowed(value);
    }
    Cow::Owned(
        value
            .chars()
            .filter(|c| !HIDDEN_CHARACTERS.contains(c))
            .collect(),
    )
}

/// `remove_surrounding_quotes`.
pub fn remove_surrounding_quotes(value: &str) -> &str {
    if let Some(quote) = value.chars().next().filter(|c| *c == '"' || *c == '\'')
        && let Some(end) = value[1..].find(quote)
    {
        return &value[1..1 + end];
    }
    value
}

/// `remove_mailto_if_not_email_address`.
pub fn remove_mailto_if_not_email_address(value: &str) -> Cow<'_, str> {
    let Ok(head) = ace_pycompat::parse::urlsplit_head(value) else {
        return Cow::Borrowed(value);
    };
    if head.scheme != "mailto" {
        return Cow::Borrowed(value);
    }
    let Ok(split) = py::urlsplit(value) else {
        return Cow::Borrowed(value);
    };
    if !py::validators_email(&split.path) {
        // value[7:]: seven characters
        return Cow::Owned(value.chars().skip(7).collect());
    }
    Cow::Borrowed(value)
}

/// `remove_null_characters`.
pub fn remove_null_characters(value: &str) -> Cow<'_, str> {
    if value.contains('\0') {
        Cow::Owned(value.replace('\0', ""))
    } else {
        Cow::Borrowed(value)
    }
}

/// For `?`: a helper's result type when it can raise.
#[allow(dead_code)]
pub type Fallible<T> = PyResult<T>;
