//! What the ported code needs of Python itself: its exceptions as data, its string methods where
//! they differ from Rust's, and `repr`. The libraries' behaviour on hostile files depends on these,
//! and 4.8 compares exception types and messages.

use std::fmt;

/// A Python exception, as `tools/library-diff/adapters/side.py`'s `error_data` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyErr {
    pub kind: String,
    pub message: String,
}

impl PyErr {
    pub fn new(kind: &str, message: impl Into<String>) -> PyErr {
        PyErr {
            kind: kind.to_owned(),
            message: message.into(),
        }
    }

    /// `except IOError`: OSError and what derives from it, which in the ported code is olefile's
    /// two errors, FileOpenError's neighbours aside, and the zipfile module's LargeZipFile doesn't.
    pub fn is_os_error(&self) -> bool {
        matches!(
            self.kind.as_str(),
            "OSError"
                | "OleFileError"
                | "NotOleFileError"
                | "FileNotFoundError"
                | "IsADirectoryError"
                | "PermissionError"
                | "BlockingIOError"
                | "TimeoutError"
        )
    }

    pub fn is_value_error(&self) -> bool {
        matches!(
            self.kind.as_str(),
            "ValueError" | "UnicodeDecodeError" | "UnicodeError" | "UnicodeEncodeError" | "Error"
        )
    }
}

impl fmt::Display for PyErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for PyErr {}

pub type PyResult<T> = Result<T, PyErr>;

/// `MemoryError`, which is what a port's limit raises where Python would run out of memory. Python
/// catches it like any `Exception`, so a limit goes down the same paths a real failure would.
pub fn memory_error() -> PyErr {
    PyErr::new("MemoryError", "")
}

/// What `str.isspace` says, and so what `\s`, `str.split()` and `str.strip()` use.
pub fn is_space(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

/// What `\w` says of a character in a `str` pattern: `str.isalnum`, or `_`.
pub fn is_word(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_alphanumeric() || c == '_';
    }
    // L* and N*: Rust's is_alphanumeric also takes the marks in Alphabetic, and Python doesn't
    is_letter_or_number(c)
}

fn is_letter_or_number(c: char) -> bool {
    use std::sync::OnceLock;
    static CLASS: OnceLock<regex::Regex> = OnceLock::new();
    let class = CLASS.get_or_init(|| regex::Regex::new(r"^[\p{L}\p{N}]$").expect("a valid class"));
    let mut buffer = [0; 4];
    class.is_match(c.encode_utf8(&mut buffer))
}

/// `str.isprintable` of one character. `repr` escapes what this refuses.
pub fn is_printable(c: char) -> bool {
    use std::sync::OnceLock;
    if c.is_ascii() {
        return (' '..='~').contains(&c);
    }
    static CLASS: OnceLock<regex::Regex> = OnceLock::new();
    let class = CLASS.get_or_init(|| regex::Regex::new(r"^[\p{C}\p{Z}]$").expect("a valid class"));
    let mut buffer = [0; 4];
    !class.is_match(c.encode_utf8(&mut buffer))
}

/// `str.splitlines()`, without the line ends.
pub fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        let is_end = matches!(
            c,
            '\n' | '\r'
                | '\u{b}'
                | '\u{c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if is_end {
            lines.push(&text[start..at]);
            let mut next = at + c.len_utf8();
            if c == '\r' && chars.peek().map(|(_, n)| *n) == Some('\n') {
                chars.next();
                next += 1;
            }
            start = next;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// `str.split(None)`.
pub fn split_whitespace(text: &str) -> Vec<&str> {
    text.split(is_space)
        .filter(|part| !part.is_empty())
        .collect()
}

/// `str.split(None, 1)`.
pub fn split_whitespace_once(text: &str) -> Vec<&str> {
    let trimmed = text.trim_start_matches(is_space);
    if trimmed.is_empty() {
        return Vec::new();
    }
    match trimmed.find(is_space) {
        None => vec![trimmed],
        Some(at) => {
            let rest = trimmed[at..].trim_start_matches(is_space);
            if rest.is_empty() {
                vec![&trimmed[..at]]
            } else {
                vec![&trimmed[..at], rest]
            }
        }
    }
}

/// `str.strip()`.
pub fn strip(text: &str) -> &str {
    text.trim_matches(is_space)
}

/// `repr(str)`.
pub fn repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if is_printable(c) => out.push(c),
            c => {
                let code = c as u32;
                if code <= 0xff {
                    out.push_str(&format!("\\x{code:02x}"));
                } else if code <= 0xffff {
                    out.push_str(&format!("\\u{code:04x}"));
                } else {
                    out.push_str(&format!("\\U{code:08x}"));
                }
            }
        }
    }
    out.push(quote);
    out
}

/// `repr(bytes)`.
pub fn repr_bytes(bytes: &[u8]) -> String {
    let quote = if bytes.contains(&b'\'') && !bytes.contains(&b'"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(bytes.len() + 3);
    out.push('b');
    out.push(quote);
    for &byte in bytes {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            byte if byte as char == quote => {
                out.push('\\');
                out.push(quote);
            }
            0x20..=0x7e => out.push(byte as char),
            byte => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out.push(quote);
    out
}

/// The `str.decode('UTF-16LE', 'replace')` of a name or a record.
pub fn decode_utf16le(bytes: &[u8]) -> String {
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    let mut out: String = char::decode_utf16(units)
        .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    if bytes.len() % 2 == 1 {
        out.push(char::REPLACEMENT_CHARACTER);
    }
    out
}

/// `struct.error` from a short read.
pub fn unpack_requires(size: usize) -> PyErr {
    PyErr::new("error", format!("unpack requires a buffer of {size} bytes"))
}

/// `struct.unpack` over `stream.read(n)`.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    pub data: &'a [u8],
    pub at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, at: 0 }
    }

    /// `read(size)`: what's left, up to size.
    pub fn read(&mut self, size: usize) -> &'a [u8] {
        let start = self.at.min(self.data.len());
        let end = start.saturating_add(size).min(self.data.len());
        self.at = end.max(self.at);
        &self.data[start..end]
    }

    pub fn u16(&mut self) -> PyResult<u16> {
        let bytes = self.read(2);
        let pair: [u8; 2] = bytes.try_into().map_err(|_| unpack_requires(2))?;
        Ok(u16::from_le_bytes(pair))
    }

    pub fn u32(&mut self) -> PyResult<u32> {
        let bytes = self.read(4);
        let four: [u8; 4] = bytes.try_into().map_err(|_| unpack_requires(4))?;
        Ok(u32::from_le_bytes(four))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitlines_is_pythons() {
        assert_eq!(
            splitlines("a\r\nb\rc\nd\u{85}e\u{2028}"),
            ["a", "b", "c", "d", "e"]
        );
        assert_eq!(splitlines("\n\n"), ["", ""]);
        assert!(splitlines("").is_empty());
    }

    #[test]
    fn repr_is_pythons() {
        assert_eq!(repr_str("a'b"), "\"a'b\"");
        assert_eq!(repr_str("a'b\""), "'a\\'b\"'");
        assert_eq!(repr_str("\u{e9}\u{ad}\u{80}\n"), "'\u{e9}\\xad\\x80\\n'");
        assert_eq!(repr_bytes(b"a\x00'"), "b\"a\\x00'\"");
    }

    #[test]
    fn a_mark_isnt_a_word_character() {
        assert!(!is_word('\u{301}'));
        assert!(is_word('\u{b2}'));
        assert!(is_word('\u{416}'));
    }
}
