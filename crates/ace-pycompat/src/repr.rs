//! `repr()` of a `str` and of `bytes`, which exception messages quote with `%r` and `!r`.

use crate::pystr::is_printable;

/// `repr(s)`.
pub fn repr(s: &str) -> String {
    repr_cps(&s.chars().map(|c| c as u32).collect::<Vec<_>>())
}

/// `repr()` of a str given as code points, which may include lone surrogates.
pub fn repr_cps(cps: &[u32]) -> String {
    let has = |c: char| cps.contains(&(c as u32));
    let quote = if has('\'') && !has('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(cps.len() + 2);
    out.push(quote);
    for &cp in cps {
        let Some(c) = char::from_u32(cp) else {
            out.push_str(&format!("\\u{cp:04x}"));
            continue;
        };
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ if c == quote => {
                out.push('\\');
                out.push(c);
            }
            _ if c.is_ascii() => {
                if (' '..='~').contains(&c) {
                    out.push(c);
                } else {
                    out.push_str(&format!("\\x{:02x}", c as u32));
                }
            }
            _ if is_printable(c) => out.push(c),
            _ => {
                let v = c as u32;
                if v <= 0xff {
                    out.push_str(&format!("\\x{v:02x}"));
                } else if v <= 0xffff {
                    out.push_str(&format!("\\u{v:04x}"));
                } else {
                    out.push_str(&format!("\\U{v:08x}"));
                }
            }
        }
    }
    out.push(quote);
    out
}

/// `repr(b)` for `bytes`.
pub fn repr_bytes(b: &[u8]) -> String {
    let quote = if b.contains(&b'\'') && !b.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    let mut out = String::with_capacity(b.len() + 3);
    out.push('b');
    out.push(quote as char);
    for &c in b {
        match c {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            _ if c == quote => {
                out.push('\\');
                out.push(c as char);
            }
            0x20..=0x7e => out.push(c as char),
            _ => out.push_str(&format!("\\x{c:02x}")),
        }
    }
    out.push(quote as char);
    out
}
