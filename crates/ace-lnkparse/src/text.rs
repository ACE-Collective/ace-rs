//! LnkParse3's `TextProcessor` with its default code page, cp1252.
//!
//! A string ends at its first NUL (a NUL byte, or a NUL UTF-16 unit at an even offset). An ANSI
//! string decodes as cp1252, then UTF-8 if cp1252 refuses it, then cp1252 with `errors="replace"`.
//! A Unicode string decodes as UTF-16LE with `errors="replace"`, as CPython does it.

/// cp1252's bytes 0x80 to 0x9F; 0 marks the five bytes cp1252 leaves undefined.
const CP1252_HIGH: [u16; 32] = [
    0x20AC, 0, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039,
    0x0152, 0, 0x017D, 0, 0, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC,
    0x2122, 0x0161, 0x203A, 0x0153, 0, 0x017E, 0x0178,
];

fn cp1252_char(b: u8) -> Option<char> {
    match b {
        0x80..=0x9F => match CP1252_HIGH[usize::from(b - 0x80)] {
            0 => None,
            cp => char::from_u32(u32::from(cp)),
        },
        _ => Some(char::from(b)),
    }
}

/// `_chars_to_string` of `read_strings`: cp1252, else UTF-8, else cp1252 with replacement.
pub(crate) fn decode_ansi(b: &[u8]) -> String {
    if let Some(s) = b
        .iter()
        .map(|&c| cp1252_char(c))
        .collect::<Option<String>>()
    {
        return s;
    }
    if let Ok(s) = std::str::from_utf8(b) {
        return s.to_owned();
    }
    b.iter()
        .map(|&c| cp1252_char(c).unwrap_or('\u{FFFD}'))
        .collect()
}

/// `read_string`: the text before the first NUL.
pub(crate) fn read_string(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    decode_ansi(&b[..end])
}

/// `read_strings`: every NUL-separated piece, the last one after the last NUL included.
pub(crate) fn read_strings(b: &[u8]) -> impl Iterator<Item = String> + '_ {
    b.split(|&c| c == 0).map(decode_ansi)
}

/// The length in bytes of the UTF-16 text before the first NUL unit at an even offset.
pub(crate) fn unicode_len(b: &[u8]) -> usize {
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] == 0 && b[i + 1] == 0 {
            return i;
        }
        i += 2;
    }
    b.len()
}

/// `read_unicode_string`: the UTF-16LE text before the first NUL unit.
pub(crate) fn read_unicode_string(b: &[u8]) -> String {
    decode_utf16le_replace(&b[..unicode_len(b)])
}

/// `bytes.decode("utf-16le", "replace")` as CPython does it: a lone surrogate is one U+FFFD,
/// and a high surrogate with fewer than two bytes after it takes the rest of the data with it.
pub(crate) fn decode_utf16le_replace(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() / 2);
    let unit = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
    let mut pos = 0;
    while pos < b.len() {
        if b.len() - pos < 2 {
            out.push('\u{FFFD}');
            break;
        }
        let u = unit(pos);
        if !(0xD800..=0xDFFF).contains(&u) {
            out.push(char::from_u32(u32::from(u)).unwrap_or('\u{FFFD}'));
            pos += 2;
        } else if u >= 0xDC00 {
            out.push('\u{FFFD}');
            pos += 2;
        } else if b.len() - pos < 4 {
            out.push('\u{FFFD}');
            break;
        } else {
            let u2 = unit(pos + 2);
            if (0xDC00..=0xDFFF).contains(&u2) {
                let cp = 0x10000 + ((u32::from(u) - 0xD800) << 10) + (u32::from(u2) - 0xDC00);
                out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                pos += 4;
            } else {
                out.push('\u{FFFD}');
                pos += 2;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_replace_matches_cpython() {
        // Recorded from Python 3.14 in ace-dev-1.
        let cases: [(&[u8], &str); 7] = [
            (b"\x00\xd8\x41", "\u{FFFD}"),
            (b"\x00\xd8", "\u{FFFD}"),
            (b"\x00\xd8\x41\x00", "\u{FFFD}A"),
            (b"\x00\xdc\x41\x00", "\u{FFFD}A"),
            (b"\x00\xd8\x00\xd8\x00\xdc", "\u{FFFD}\u{10000}"),
            (b"\x41", "\u{FFFD}"),
            (b"\x00\xd8\x00\xdc\x41", "\u{10000}\u{FFFD}"),
        ];
        for (b, want) in cases {
            assert_eq!(decode_utf16le_replace(b), want, "{b:?}");
        }
    }

    #[test]
    fn ansi_fallbacks() {
        assert_eq!(decode_ansi(b"caf\xe9 \x80"), "caf\u{e9} \u{20ac}");
        assert_eq!(decode_ansi(b"\xc3\x81"), "\u{c1}");
        assert_eq!(decode_ansi(b"\x81A"), "\u{FFFD}A");
        assert_eq!(read_strings(b"a\0").collect::<Vec<_>>(), ["a", ""]);
        assert_eq!(read_strings(b"").collect::<Vec<_>>(), [""]);
    }
}
