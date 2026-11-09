//! `html.escape` and `html.unescape` of Python 3.14.
//!
//! `unescape` finds references with Python's pattern,
//! `&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\f <&#;]{1,32};?)`. A named reference that isn't in
//! `html5` takes the longest prefix of at least two characters that is, as the standard says for
//! one without a `;`; numeric references follow the invalid-reference table.

pub mod entities;

use std::borrow::Cow;

/// `html.escape(s, quote)`.
pub fn escape(s: &str, quote: bool) -> Cow<'_, str> {
    let special = |c: char| matches!(c, '&' | '<' | '>') || (quote && matches!(c, '"' | '\''));
    if !s.contains(special) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if quote => out.push_str("&quot;"),
            '\'' if quote => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// `html.unescape(s)`.
pub fn unescape(s: &str) -> Cow<'_, str> {
    if !s.contains('&') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        match reference(after) {
            Some(len) => {
                replace(&after[..len], &mut out);
                rest = &after[len..];
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

/// The length of the reference `_charref` matches after a `&`, if it matches one.
fn reference(after: &str) -> Option<usize> {
    let b = after.as_bytes();
    let with_semicolon = |end: usize| {
        if b.get(end) == Some(&b';') {
            end + 1
        } else {
            end
        }
    };
    if b.first() == Some(&b'#') {
        let digits = b[1..].iter().take_while(|c| c.is_ascii_digit()).count();
        if digits > 0 {
            return Some(with_semicolon(1 + digits));
        }
        if matches!(b.get(1), Some(b'x' | b'X')) {
            let hex = b[2..].iter().take_while(|c| c.is_ascii_hexdigit()).count();
            if hex > 0 {
                return Some(with_semicolon(2 + hex));
            }
        }
        return None;
    }
    let mut end = 0;
    for (count, (i, c)) in after.char_indices().enumerate() {
        if count == 32 || matches!(c, '\t' | '\n' | '\x0c' | ' ' | '<' | '&' | '#' | ';') {
            break;
        }
        end = i + c.len_utf8();
    }
    (end > 0).then(|| with_semicolon(end))
}

/// `_replace_charref` for the reference `s` (without its `&`), appended to `out`.
fn replace(s: &str, out: &mut String) {
    if let Some(num) = s.strip_prefix('#') {
        out.push_str(&entities::numeric(num.trim_end_matches(';')));
        return;
    }
    if let Some(v) = entities::html5(s) {
        out.push_str(v);
        return;
    }
    // The longest prefix of at least two characters that is a name, shortest last.
    let bounds: Vec<usize> = s.char_indices().map(|(i, _)| i).collect();
    for x in (2..bounds.len()).rev() {
        let (name, tail) = s.split_at(bounds[x]);
        if let Some(v) = entities::html5(name) {
            out.push_str(v);
            out.push_str(tail);
            return;
        }
    }
    out.push('&');
    out.push_str(s);
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::testdata::{Mismatches, s};

    #[test]
    fn escape_and_unescape_match_python() {
        let data: Value = crate::testdata::load("html", include_str!("../tests/data/html.json"));
        let mut m = Mismatches::new("html");
        for case in data.as_array().unwrap() {
            let x = s(case, "s");
            let got = json!({
                "s": x, "unescape": unescape(x), "escape": escape(x, true), "escape_noquote": escape(x, false),
            });
            m.check(x, &got, case);
        }
        m.finish();
    }
}
