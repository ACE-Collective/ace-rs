//! Python behaviour the port leans on: slices, struct errors, repr, float str, codecs.

use crate::XlError;
use crate::dbcs;
use crate::tables::{NONPRINTABLE, SINGLE_BYTE};

pub(crate) type R<T> = Result<T, XlError>;

pub(crate) fn err(kind: &str, message: impl Into<String>) -> XlError {
    XlError {
        kind: kind.to_string(),
        message: message.into(),
    }
}

pub(crate) fn xlrd_err(message: impl Into<String>) -> XlError {
    err("XLRDError", message)
}

pub(crate) fn assertion() -> XlError {
    err("AssertionError", "")
}

pub(crate) fn memory_error() -> XlError {
    err("MemoryError", "")
}

pub(crate) fn unbound(name: &str) -> XlError {
    err(
        "UnboundLocalError",
        format!("cannot access local variable '{name}' where it is not associated with a value"),
    )
}

/// `s[start:stop]` with Python's negative index and clamping rules.
pub(crate) fn slice(d: &[u8], start: i64, stop: i64) -> &[u8] {
    let len = d.len() as i64;
    let fix = |i: i64| -> usize {
        let i = if i < 0 { i.saturating_add(len) } else { i };
        i.clamp(0, len) as usize
    };
    let (a, b) = (fix(start), fix(stop));
    if a >= b {
        return &[];
    }
    d.get(a..b).unwrap_or(&[])
}

/// `s[start:]`.
pub(crate) fn from(d: &[u8], start: i64) -> &[u8] {
    slice(d, start, d.len() as i64)
}

/// `s[start:start+n]`, as most of the source writes it.
pub(crate) fn span(d: &[u8], start: i64, n: i64) -> &[u8] {
    slice(d, start, start.saturating_add(n))
}

/// struct.unpack's check: the buffer must be exactly the format's size.
pub(crate) fn need(d: &[u8], n: usize) -> R<&[u8]> {
    if d.len() == n {
        Ok(d)
    } else {
        Err(err(
            "error",
            format!("unpack requires a buffer of {n} bytes"),
        ))
    }
}

pub(crate) fn u8_at(d: &[u8], i: usize) -> u8 {
    d.get(i).copied().unwrap_or(0)
}

pub(crate) fn u16_at(d: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([u8_at(d, i), u8_at(d, i + 1)])
}

pub(crate) fn i16_at(d: &[u8], i: usize) -> i16 {
    u16_at(d, i) as i16
}

pub(crate) fn u32_at(d: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([
        u8_at(d, i),
        u8_at(d, i + 1),
        u8_at(d, i + 2),
        u8_at(d, i + 3),
    ])
}

pub(crate) fn i32_at(d: &[u8], i: usize) -> i32 {
    u32_at(d, i) as i32
}

pub(crate) fn f64_at(d: &[u8], i: usize) -> f64 {
    let mut b = [0u8; 8];
    for (k, v) in b.iter_mut().enumerate() {
        *v = u8_at(d, i + k);
    }
    f64::from_le_bytes(b)
}

/// `data[pos]` on bytes.
pub(crate) fn byte_at(d: &[u8], pos: i64) -> R<u8> {
    py_index(pos as i128, d.len())
        .and_then(|i| d.get(i).copied())
        .ok_or_else(|| err("IndexError", "index out of range"))
}

/// Python's index normalisation; None is IndexError.
pub(crate) fn py_index(i: i128, len: usize) -> Option<usize> {
    let l = len as i128;
    let i = if i < 0 { i + l } else { i };
    if (0..l).contains(&i) {
        Some(i as usize)
    } else {
        None
    }
}

pub(crate) fn list_index_error() -> XlError {
    err("IndexError", "list index out of range")
}

/// repr(bytes).
pub(crate) fn repr_bytes(d: &[u8]) -> String {
    let quote = if d.contains(&b'\'') && !d.contains(&b'"') {
        '"'
    } else {
        '\''
    };
    let mut s = String::with_capacity(d.len() + 3);
    s.push('b');
    s.push(quote);
    for &c in d {
        match c {
            b'\\' => s.push_str("\\\\"),
            b'\t' => s.push_str("\\t"),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            _ if c as char == quote => {
                s.push('\\');
                s.push(quote);
            }
            0x20..=0x7e => s.push(c as char),
            _ => s.push_str(&format!("\\x{c:02x}")),
        }
    }
    s.push(quote);
    s
}

fn is_printable(c: char) -> bool {
    let c = c as u32;
    NONPRINTABLE
        .binary_search_by(|&(a, b)| {
            if c < a {
                std::cmp::Ordering::Greater
            } else if c > b {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_err()
}

fn push_u_escape(s: &mut String, c: u32) {
    if c < 0x100 {
        s.push_str(&format!("\\x{c:02x}"));
    } else if c < 0x10000 {
        s.push_str(&format!("\\u{c:04x}"));
    } else {
        s.push_str(&format!("\\U{c:08x}"));
    }
}

fn repr_with(t: &str, keep_printable: bool) -> String {
    let quote = if t.contains('\'') && !t.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut s = String::with_capacity(t.len() + 2);
    s.push(quote);
    for c in t.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '\t' => s.push_str("\\t"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            _ if c == quote => {
                s.push('\\');
                s.push(quote);
            }
            ' '..='~' => s.push(c),
            _ if keep_printable && (c as u32) >= 0x80 && is_printable(c) => s.push(c),
            _ => push_u_escape(&mut s, c as u32),
        }
    }
    s.push(quote);
    s
}

/// repr(str).
pub(crate) fn repr_str(t: &str) -> String {
    repr_with(t, true)
}

/// ascii(str): what xlrd's fprintf makes of %r.
pub(crate) fn ascii_str(t: &str) -> String {
    repr_with(t, false)
}

/// ascii(x) given repr(x): non-ASCII characters become escapes.
pub(crate) fn ascii_str_repr(repr: &str) -> String {
    let mut s = String::with_capacity(repr.len());
    for c in repr.chars() {
        if c.is_ascii() {
            s.push(c);
        } else {
            push_u_escape(&mut s, c as u32);
        }
    }
    s
}

/// Python's float repr without the trailing `.0` rule: format code 'r'.
fn float_digits(x: f64, add_dot0: bool) -> String {
    if x.is_nan() {
        return "nan".to_string();
    }
    if x.is_infinite() {
        return if x > 0.0 { "inf" } else { "-inf" }.to_string();
    }
    let sci = format!("{x:e}");
    let (mant, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let (sign, mant) = match mant.strip_prefix('-') {
        Some(m) => ("-", m),
        None => ("", mant),
    };
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let mut out = String::from(sign);
    if (-4..16).contains(&exp) {
        if exp < 0 {
            out.push_str("0.");
            out.push_str(&"0".repeat((-exp - 1) as usize));
            out.push_str(&digits);
        } else {
            let point = exp as usize + 1;
            if digits.len() <= point {
                out.push_str(&digits);
                out.push_str(&"0".repeat(point - digits.len()));
                if add_dot0 {
                    out.push_str(".0");
                }
            } else {
                let (a, b) = digits.split_at(point);
                out.push_str(a);
                out.push('.');
                out.push_str(b);
            }
        }
    } else {
        let (a, b) = digits.split_at(1);
        out.push_str(a);
        if !b.is_empty() {
            out.push('.');
            out.push_str(b);
        }
        let e = exp.unsigned_abs();
        out.push_str(&format!("e{}{e:02}", if exp < 0 { '-' } else { '+' },));
    }
    out
}

/// str(float).
pub fn float_repr(x: f64) -> String {
    float_digits(x, true)
}

/// str(complex).
pub(crate) fn complex_repr(re: f64, im: f64) -> String {
    let imag = float_digits(im, false);
    if re == 0.0 && re.is_sign_positive() {
        return format!("{imag}j");
    }
    let sep = if im.is_sign_negative() || im.is_nan() && imag.starts_with('-') {
        ""
    } else {
        "+"
    };
    format!("({}{sep}{imag}j)", float_digits(re, false))
}

/// A codec as derive_encoding names it. `name` is what the Python code passes to decode.
#[derive(Clone)]
pub(crate) struct Encoding {
    pub(crate) name: String,
    codec: Codec,
}

#[derive(Clone, Copy)]
enum Codec {
    Latin1,
    Ascii,
    Utf16Le,
    Table(&'static [u16; 256]),
    Double(dbcs::Double),
    Unknown,
}

impl Encoding {
    pub(crate) fn named(name: &str) -> Encoding {
        let codec = match name {
            "iso-8859-1" | "latin_1" | "cp819" => Codec::Latin1,
            "cp367" => Codec::Ascii,
            "utf_16_le" => Codec::Utf16Le,
            "cp932" => Codec::Double(dbcs::Double::Cp932),
            "cp936" => Codec::Double(dbcs::Double::Gbk),
            "cp949" => Codec::Double(dbcs::Double::Cp949),
            "cp950" => Codec::Double(dbcs::Double::Cp950),
            "cp1361" => Codec::Double(dbcs::Double::Johab),
            _ => SINGLE_BYTE
                .iter()
                .find(|(names, _)| names.contains(&name))
                .map_or(Codec::Unknown, |(_, t)| Codec::Table(t)),
        };
        Encoding {
            name: name.to_string(),
            codec,
        }
    }

    /// `bytes.decode(self.name)`.
    pub(crate) fn decode(&self, d: &[u8]) -> R<String> {
        match self.codec {
            Codec::Latin1 => Ok(latin1(d)),
            Codec::Ascii => ascii(d),
            Codec::Utf16Le => utf16le(d),
            Codec::Table(t) => {
                let mut s = String::with_capacity(d.len());
                for (i, &b) in d.iter().enumerate() {
                    let c = t
                        .get(b as usize)
                        .copied()
                        .filter(|c| *c != 0xffff)
                        .and_then(|c| char::from_u32(c as u32));
                    match c {
                        Some(c) => s.push(c),
                        None => {
                            return Err(decode_error(
                                "charmap",
                                d,
                                i,
                                i + 1,
                                "character maps to <undefined>",
                            ));
                        }
                    }
                }
                Ok(s)
            }
            Codec::Double(k) => dbcs::decode(k, d),
            Codec::Unknown => Err(err(
                "LookupError",
                format!("unknown encoding: {}", self.name),
            )),
        }
    }
}

pub(crate) fn decode_error(
    codec: &str,
    d: &[u8],
    start: usize,
    end: usize,
    reason: &str,
) -> XlError {
    let msg = if end == start + 1 {
        format!(
            "'{codec}' codec can't decode byte 0x{:02x} in position {start}: {reason}",
            u8_at(d, start)
        )
    } else {
        format!(
            "'{codec}' codec can't decode bytes in position {start}-{}: {reason}",
            end - 1
        )
    };
    err("UnicodeDecodeError", msg)
}

/// `bytes.decode('latin_1')`.
pub(crate) fn latin1(d: &[u8]) -> String {
    d.iter().map(|&b| b as char).collect()
}

/// `bytes.decode('ascii')`.
pub(crate) fn ascii(d: &[u8]) -> R<String> {
    if let Some(i) = d.iter().position(|b| *b >= 0x80) {
        return Err(decode_error(
            "ascii",
            d,
            i,
            i + 1,
            "ordinal not in range(128)",
        ));
    }
    Ok(latin1(d))
}

/// `bytes.decode('utf_16_le')` with the strict decoder's errors.
pub(crate) fn utf16le(d: &[u8]) -> R<String> {
    const CODEC: &str = "utf-16-le";
    let mut s = String::with_capacity(d.len() / 2);
    let mut q = 0usize;
    let e = d.len();
    while q + 1 < e {
        let ch = u16_at(d, q) as u32;
        q += 2;
        if !(0xd800..0xe000).contains(&ch) {
            if let Some(c) = char::from_u32(ch) {
                s.push(c);
            }
            continue;
        }
        if ch >= 0xdc00 {
            return Err(decode_error(CODEC, d, q - 2, q, "illegal encoding"));
        }
        if q + 1 >= e {
            return Err(decode_error(CODEC, d, q - 2, e, "unexpected end of data"));
        }
        let lo = u16_at(d, q) as u32;
        q += 2;
        if !(0xdc00..0xe000).contains(&lo) {
            return Err(decode_error(
                CODEC,
                d,
                q - 4,
                q - 2,
                "illegal UTF-16 surrogate",
            ));
        }
        if let Some(c) = char::from_u32(0x10000 + ((ch - 0xd800) << 10) + (lo - 0xdc00)) {
            s.push(c);
        }
    }
    if q < e {
        return Err(decode_error(CODEC, d, q, e, "truncated data"));
    }
    Ok(s)
}

/// biffh.unpack_string; `enc` of None is decode(None), a TypeError.
pub(crate) fn unpack_string(d: &[u8], pos: i64, enc: Option<&Encoding>, lenlen: i64) -> R<String> {
    let head = span(d, pos, lenlen);
    let nchars = unpack_len(head, lenlen)?;
    let pos = pos + lenlen;
    decode_opt(span(d, pos, nchars), enc)
}

pub(crate) fn decode_opt(d: &[u8], enc: Option<&Encoding>) -> R<String> {
    match enc {
        Some(e) => e.decode(d),
        None => Err(err(
            "TypeError",
            "decode() argument 'encoding' must be str, not None",
        )),
    }
}

fn unpack_len(head: &[u8], lenlen: i64) -> R<i64> {
    if lenlen == 1 {
        Ok(need(head, 1)?.first().copied().unwrap_or(0) as i64)
    } else {
        Ok(u16_at(need(head, 2)?, 0) as i64)
    }
}

/// biffh.unpack_string_update_pos.
pub(crate) fn unpack_string_update_pos(
    d: &[u8],
    pos: i64,
    enc: Option<&Encoding>,
    lenlen: i64,
    known_len: Option<i64>,
) -> R<(String, i64)> {
    let (nchars, pos) = match known_len {
        Some(n) => (n, pos),
        None => (unpack_len(span(d, pos, lenlen), lenlen)?, pos + lenlen),
    };
    let newpos = pos + nchars;
    Ok((decode_opt(slice(d, pos, newpos), enc)?, newpos))
}

/// biffh.unpack_unicode.
pub(crate) fn unpack_unicode(d: &[u8], pos: i64, lenlen: i64) -> R<String> {
    let nchars = unpack_len(span(d, pos, lenlen), lenlen)?;
    if nchars == 0 {
        return Ok(String::new());
    }
    let mut pos = pos + lenlen;
    let options = byte_at(d, pos)?;
    pos += 1;
    if options & 0x08 != 0 {
        pos += 2;
    }
    if options & 0x04 != 0 {
        pos += 4;
    }
    if options & 0x01 != 0 {
        utf16le(span(d, pos, 2 * nchars))
    } else {
        Ok(latin1(span(d, pos, nchars)))
    }
}

/// biffh.unpack_unicode_update_pos.
pub(crate) fn unpack_unicode_update_pos(
    d: &[u8],
    pos: i64,
    lenlen: i64,
    known_len: Option<i64>,
) -> R<(String, i64)> {
    let (nchars, mut pos) = match known_len {
        Some(n) => (n, pos),
        None => (unpack_len(span(d, pos, lenlen), lenlen)?, pos + lenlen),
    };
    if nchars == 0 && from(d, pos).is_empty() {
        return Ok((String::new(), pos));
    }
    let options = byte_at(d, pos)?;
    pos += 1;
    let phonetic = options & 0x04 != 0;
    let richtext = options & 0x08 != 0;
    let mut rt = 0i64;
    let mut sz = 0i64;
    if richtext {
        rt = u16_at(need(span(d, pos, 2), 2)?, 0) as i64;
        pos += 2;
    }
    if phonetic {
        sz = i32_at(need(span(d, pos, 4), 4)?, 0) as i64;
        pos += 4;
    }
    let strg;
    if options & 0x01 != 0 {
        strg = utf16le(span(d, pos, 2 * nchars))?;
        pos += 2 * nchars;
    } else {
        strg = latin1(span(d, pos, nchars));
        pos += nchars;
    }
    if richtext {
        pos += 4 * rt;
    }
    if phonetic {
        pos += sz;
    }
    Ok((strg, pos))
}

/// biffh.hex_char_dump with base 0, numbered.
pub(crate) fn hex_char_dump(log: &mut String, strg: &[u8], ofs: i64, dlen: i64) {
    let endpos = (ofs + dlen).min(strg.len() as i64);
    let mut pos = ofs;
    while pos < endpos {
        let endsub = (pos + 16).min(endpos);
        let sub = slice(strg, pos, endsub);
        let hexd: String = sub.iter().map(|c| format!("{c:02x} ")).collect();
        let chard: String = sub
            .iter()
            .map(|&c| match c {
                0 => '~',
                0x20..=0x7e => c as char,
                _ => '?',
            })
            .collect();
        log.push_str(&format!("{:5}:      {hexd:<48} {chard}\n", pos - ofs));
        pos = endsub;
    }
}

/// `float(str)`; ASCII digits only.
pub(crate) fn py_float(t: &str) -> R<f64> {
    let bad = || {
        err(
            "ValueError",
            format!("could not convert string to float: {}", repr_str(t)),
        )
    };
    let body = t.trim_matches(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c));
    let cleaned: String = if body.contains('_') {
        let b: Vec<char> = body.chars().collect();
        for (i, c) in b.iter().enumerate() {
            let ok = *c != '_'
                || (i > 0
                    && b.get(i - 1).is_some_and(char::is_ascii_digit)
                    && b.get(i + 1).is_some_and(char::is_ascii_digit));
            if !ok {
                return Err(bad());
            }
        }
        b.into_iter().filter(|c| *c != '_').collect()
    } else {
        body.to_string()
    };
    if cleaned.is_empty() {
        return Err(bad());
    }
    cleaned.parse::<f64>().map_err(|_| bad())
}
