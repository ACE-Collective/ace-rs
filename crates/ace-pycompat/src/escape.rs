//! `bytes.decode('unicode_escape', 'replace')`, as ace3's JSON encoder writes bytes in a result's
//! details (`saq/json_encoding.py`), and as the email package decodes with that codec.

use memchr::memchr;

/// `\x`, `\u` or `\U` and `count` hex digits from `at`, which it moves past the digits it
/// reads: the code point, or None when a digit is missing or it's past U+10FFFF, which 'replace'
/// makes U+FFFD.
pub fn hex_escape(raw: &[u8], at: &mut usize, count: usize) -> Option<u32> {
    let mut code = 0u32;
    for _ in 0..count {
        let digit = raw.get(*at).and_then(|&b| char::from(b).to_digit(16))?;
        code = (code << 4) + digit;
        *at += 1;
    }
    (code <= 0x10ffff).then_some(code)
}

/// `_PyUnicode_DecodeUnicodeEscapeInternal` with 'replace'. There is no name database here, so every
/// `\N{...}` is an unknown name.
pub fn decode_unicode_escape(raw: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity(raw.len());
    let mut at = 0;
    while at < raw.len() {
        let byte = raw[at];
        at += 1;
        if byte != b'\\' {
            out.push(u32::from(byte));
            continue;
        }
        let Some(&next) = raw.get(at) else {
            out.push(0xfffd);
            break;
        };
        at += 1;
        match next {
            b'\n' => {}
            b'\\' | b'\'' | b'"' => out.push(u32::from(next)),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b't' => out.push(9),
            b'n' => out.push(10),
            b'r' => out.push(13),
            b'v' => out.push(11),
            b'a' => out.push(7),
            b'0'..=b'7' => {
                let mut code = u32::from(next - b'0');
                for _ in 0..2 {
                    match raw.get(at) {
                        Some(&digit @ b'0'..=b'7') => {
                            code = (code << 3) + u32::from(digit - b'0');
                            at += 1;
                        }
                        _ => break,
                    }
                }
                out.push(code);
            }
            b'x' => out.push(hex_escape(raw, &mut at, 2).unwrap_or(0xfffd)),
            b'u' => out.push(hex_escape(raw, &mut at, 4).unwrap_or(0xfffd)),
            b'U' => out.push(hex_escape(raw, &mut at, 8).unwrap_or(0xfffd)),
            b'N' => {
                if raw.get(at) == Some(&b'{') {
                    at += 1;
                    match memchr(b'}', &raw[at..]) {
                        None => at = raw.len(),
                        Some(0) => {}
                        Some(length) => at += length + 1,
                    }
                }
                out.push(0xfffd);
            }
            _ => {
                out.push(u32::from(b'\\'));
                out.push(u32::from(next));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(raw: &[u8]) -> String {
        decode_unicode_escape(raw)
            .into_iter()
            .map(|c| char::from_u32(c).unwrap_or('\u{fffd}'))
            .collect()
    }

    #[test]
    fn escapes_decode_as_pythons_unicode_escape() {
        // a Windows path in unautoit's listing, as ace3 stores it
        assert_eq!(
            decode(br"C:\Users\Matthew\aut6D74.tmp"),
            "C:\u{fffd}sers\\Matthew\u{7}ut6D74.tmp"
        );
        assert_eq!(decode(br"\x41\u00e9\101\n"), "A\u{e9}A\n");
        assert_eq!(decode(b"\xff tail \\"), "\u{ff} tail \u{fffd}");
        assert_eq!(decode(br"\N{DASH}x"), "\u{fffd}x");
    }
}
