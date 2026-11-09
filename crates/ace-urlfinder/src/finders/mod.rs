//! `urlfinderlib/finders/`: one finder per kind of blob. Each hands its candidates to the text
//! finder and returns `distinct_values()`.

pub mod html;
mod ical;
pub mod text;

use std::collections::BTreeSet;

use crate::py::{self, PyErr, PyResult};
use crate::tokenizer::Tokenizer;
use crate::url::UrlList;

/// `UrlList() += TextUrlFinder(s).find_urls(strict=True)` for each candidate.
fn through_text<'s>(candidates: impl IntoIterator<Item = &'s str>) -> PyResult<BTreeSet<String>> {
    let mut urls = UrlList::new();
    for candidate in candidates {
        urls.extend(&text::find_urls(candidate.as_bytes(), false)?)?;
    }
    urls.distinct_values()
}

/// `DataUrlFinder`: printable ASCII runs of eight or more that look like they hold a URL.
pub fn data(blob: &[u8]) -> PyResult<BTreeSet<String>> {
    let tok = Tokenizer::new(blob);
    let possible: BTreeSet<&str> = tok
        .ascii_strings(8)
        .into_iter()
        .filter(|s| (s.contains(':') || s.contains('/')) && s.contains('.'))
        .collect();
    through_text(possible)
}

/// `CsvUrlFinder`: each field with a dot and a slash.
pub fn csv(blob: &[u8]) -> PyResult<BTreeSet<String>> {
    let text = py::decode_utf8_ignore(blob);
    let (rows, error) = ace_pycompat::csv::read_all(&text);
    if let Some(error) = error {
        return Err(error);
    }
    let possible: BTreeSet<&str> = rows
        .iter()
        .flatten()
        .map(String::as_str)
        .filter(|item| item.contains('.') && item.contains('/'))
        .collect();
    through_text(possible)
}

const PDF_PAIRS: [(&str, &str); 17] = [
    ("/URI", ">>"),
    ("(http", ")"),
    ("(ftp", ")"),
    ("<http", ">"),
    ("<ftp", ">"),
    ("\"http", "\""),
    ("\"ftp", "\""),
    ("'http", "'"),
    ("'ftp", "'"),
    ("(HTTP", ")"),
    ("(FTP", ")"),
    ("<HTTP", ">"),
    ("<FTP", ">"),
    ("\"HTTP", "\""),
    ("\"FTP", "\""),
    ("'HTTP", "'"),
    ("'FTP", "'"),
];

/// `re.sub(rb"\\x[a-f0-9]{2,}", b" ", blob)`.
fn replace_hex_escapes(blob: &[u8]) -> Vec<u8> {
    let hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    let mut out = Vec::with_capacity(blob.len());
    let mut i = 0;
    while i < blob.len() {
        if blob[i] == b'\\' && blob.get(i + 1) == Some(&b'x') {
            let mut end = i + 2;
            while end < blob.len() && hex(blob[end]) {
                end += 1;
            }
            if end - (i + 2) >= 2 {
                out.push(b' ');
                i = end;
                continue;
            }
        }
        out.push(blob[i]);
        i += 1;
    }
    out
}

/// `PdfUrlFinder`.
pub fn pdf(blob: &[u8]) -> PyResult<BTreeSet<String>> {
    let blob = replace_hex_escapes(blob);
    let tok = Tokenizer::new(&blob);
    let mut tokens: BTreeSet<String> = BTreeSet::new();
    for (open, close) in PDF_PAIRS {
        for token in tok.between_open_and_close(open, close) {
            let token = token.replace('\\', "");
            // token.split()[0], an IndexError where the token is only whitespace
            let first = crate::tokenizer::split_on_space(&token)
                .next()
                .ok_or_else(|| PyErr::builtin("IndexError", "list index out of range"))?;
            tokens.insert(first.to_owned());
        }
    }
    let mut urls = UrlList::new();
    for token in &tokens {
        urls.extend(&text::find_urls(token.as_bytes(), false)?)?;
    }
    urls.distinct_values()
}

/// `XmlUrlFinder`: ElementTree on expat, the root's repr, every tag, attribute name and value,
/// and every element's text.
pub fn xml(blob: &[u8]) -> PyResult<BTreeSet<String>> {
    use ace_mod_oletools::pyxml;
    let text = py::decode_utf8_ignore(blob);
    let root = match pyxml::fromstring_str(&text) {
        Ok(root) => root,
        Err(e) if e.kind == "ParseError" => {
            pyxml::fromstring_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?><empty></empty>")
                .map_err(oletools_error)?
        }
        Err(e) => return Err(oletools_error(e)),
    };
    let mut possible: BTreeSet<String> = BTreeSet::new();
    // str(root): "<Element 'tag' at 0x...>"; the address holds no dot or slash
    possible.insert(format!(
        "<Element {} at 0x7f0000000000>",
        ace_pycompat::repr::repr(&root.tag)
    ));
    for element in root.iter_tag("*") {
        if element.tag.contains('.') && element.tag.contains('/') {
            possible.insert(element.tag.clone());
        }
        for (name, value) in &element.attrib {
            for item in [name, value] {
                if item.contains('.') && item.contains('/') {
                    possible.insert(item.clone());
                }
            }
        }
        if let Some(text) = &element.text
            && text.contains('.')
            && text.contains('/')
        {
            possible.insert(text.clone());
        }
    }
    through_text(possible.iter().map(String::as_str))
}

/// An exception from the ElementTree port, as this crate's.
fn oletools_error(e: ace_mod_oletools::py::PyErr) -> PyErr {
    let kind = match e.kind.as_str() {
        "MemoryError" => "MemoryError",
        "OverflowError" => "OverflowError",
        "RecursionError" => "RecursionError",
        "ValueError" => "ValueError",
        "UnicodeDecodeError" => "UnicodeDecodeError",
        "LookupError" => "LookupError",
        _ => "Exception",
    };
    PyErr::builtin(kind, e.message.clone())
}

/// `IcalUrlFinder`.
pub fn ical(blob: &[u8]) -> PyResult<BTreeSet<String>> {
    let text = py::decode_utf8_ignore(blob);
    let mut urls = UrlList::new();
    for line in ical::content_lines(&text) {
        match ical::parts(&line) {
            Err(()) => urls.extend(&text::find_urls(line.as_bytes(), false)?)?,
            Ok((fmttype, value)) => {
                let value = ical::unescape_char(&value);
                if py::lower(&fmttype).starts_with("text/html") {
                    urls.extend(&html::find_urls(value.as_bytes(), "")?)?;
                } else {
                    urls.extend(&text::find_urls(value.as_bytes(), false)?)?;
                }
            }
        }
    }
    urls.distinct_values()
}
