//! A port of urlfinderlib 0.27.1, the library ace3's `url_extraction` and `ioc_extraction` find
//! URLs with: `find_urls`, `find_urls_in_text`, and the `URL` class with its child URLs
//! ([`Url`], [`child_urls`]), which other modules can use too, such as the clicker module's
//! search for a URL's children.
//!
//! It follows urlfinderlib line by line, on ports of what it calls: Python's `urllib.parse`,
//! `html`, `base64`, `json`, `csv` and `unicodedata`, and the idna, validators and tld packages
//! (`ace-pycompat`), ElementTree on expat (`ace-mod-oletools`), lxml's HTML parser, which is
//! libxml2 itself (`ace-lxml`), and libmagic, which is libmagic itself. What Python would raise
//! comes back as an `Err` with the exception, from wherever Python would have raised it.
//!
//! Python returns sets. Here they are `BTreeSet`s, so the order is the strings' order, where
//! Python's changes with each process's hash seed.

pub mod finders;
mod helpers;
pub mod magic;
mod py;
mod pyjson;
mod tokenizer;
pub mod url;

use std::collections::BTreeSet;

pub use ace_pycompat::PyErr;
pub use magic::Magic;
pub use url::{Url, UrlList, child_urls};

use crate::py::PyResult;

/// What servers put before JSON so a page can't load it as a script.
const JSON_HIJACKING_PREFIXES: [&str; 3] = [")]}'", "while(1);", "for(;;);"];

/// A JSON document in a JSON string is read again, this many levels down at most.
const MAX_JSON_DEPTH: u32 = 3;

/// `base64_encoded_url_pattern`: a base64 run, starting where no base64 character is before
/// it, that opens with the encoding of "http" or "ftp".
fn base64_encoded_urls(blob: &[u8]) -> PyResult<BTreeSet<String>> {
    let text = py::decode_utf8_ignore(blob);
    let bytes = text.as_bytes();
    let class = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'-');
    let mut urls = BTreeSet::new();
    let mut i = 0;
    while i < bytes.len() {
        let starts = (bytes[i..].starts_with(b"aHR0c") || bytes[i..].starts_with(b"ZnRw"))
            && (i == 0 || !class(bytes[i - 1]));
        if !starts {
            i += 1;
            continue;
        }
        let prefix = if bytes[i] == b'a' { 5 } else { 4 };
        let mut end = i + prefix;
        while end < bytes.len() && class(bytes[end]) {
            end += 1;
        }
        if end == i + prefix {
            i += 1;
            continue;
        }
        let mut with_padding = end;
        while with_padding < bytes.len() && with_padding < end + 2 && bytes[with_padding] == b'=' {
            with_padding += 1;
        }
        let decoded = helpers::decode_base64_ascii(&text[i..with_padding]);
        if !decoded.is_empty() {
            urls.extend(finders::text::find_urls(decoded.as_bytes(), false)?);
        }
        i = with_padding;
    }
    Ok(urls)
}

/// `_json_strings`: every string of a JSON document, keys too, or None when it isn't one.
fn json_strings(blob: &[u8]) -> PyResult<Option<Vec<String>>> {
    let text = py::decode_utf8_ignore(blob);
    let mut text = py::strip(&text);
    for prefix in JSON_HIJACKING_PREFIXES {
        if let Some(rest) = text.strip_prefix(prefix) {
            text = ace_pycompat::pystr::lstrip(rest);
            break;
        }
    }
    if !(text.starts_with('{') || text.starts_with('[')) {
        return Ok(None);
    }
    pyjson::strings(text)
}

/// `_is_maybe_csv`: every line has a comma, and as many as the first.
fn is_maybe_csv(blob: &[u8]) -> bool {
    let text = py::decode_utf8_ignore(blob);
    let lines = py::splitlines(&text);
    let Some(first) = lines.first() else {
        return false;
    };
    let commas = first.matches(',').count();
    lines.iter().all(|line| line.contains(','))
        && lines.iter().all(|line| line.matches(',').count() == commas)
}

/// `_remove_utf16_chars`: the UTF-16 little-endian byte order marks at the start, then every NUL.
fn remove_utf16_chars(blob: &[u8]) -> Vec<u8> {
    // bytes.lstrip(BOM_UTF16) strips any of the BOM's bytes, little-endian here
    let start = blob
        .iter()
        .position(|b| *b != 0xff && *b != 0xfe)
        .unwrap_or(blob.len());
    blob[start..].iter().copied().filter(|b| *b != 0).collect()
}

/// The URLs in a blob, as `urlfinderlib.find_urls` finds them.
pub struct Finder<'m> {
    magic: &'m Magic,
}

impl<'m> Finder<'m> {
    pub fn new(magic: &'m Magic) -> Finder<'m> {
        Finder { magic }
    }

    /// `find_urls(blob, base_url, mimetype, domain_as_url)`.
    pub fn find_urls(
        &self,
        blob: &[u8],
        base_url: &str,
        mimetype: &str,
        domain_as_url: bool,
    ) -> PyResult<BTreeSet<String>> {
        let urls = self.candidates(
            blob,
            base_url,
            mimetype,
            domain_as_url,
            MAX_JSON_DEPTH,
            false,
        )?;
        distinct_urls(urls, domain_as_url)
    }

    fn candidates(
        &self,
        blob: &[u8],
        base_url: &str,
        mimetype: &str,
        domain_as_url: bool,
        json_depth: u32,
        json_string: bool,
    ) -> PyResult<Vec<String>> {
        let mut blob = std::borrow::Cow::Borrowed(blob);
        let mut mimetype = if mimetype.is_empty() {
            self.magic.from_buffer(&blob)?
        } else {
            mimetype.to_owned()
        };
        mimetype = py::lower(&mimetype).into_owned();
        if mimetype.contains("utf-16") {
            blob = std::borrow::Cow::Owned(remove_utf16_chars(&blob));
            mimetype = self.magic.from_buffer(&blob)?;
        }
        let mimetype = py::lower(&mimetype).into_owned();

        let mut urls: Vec<String> = Vec::new();
        if mimetype.contains("rfc 822") || mimetype.contains("mail") {
            return Ok(urls);
        } else if mimetype.contains("html") {
            blob = std::borrow::Cow::Owned(helpers::unescape_ascii(&blob));
            urls.extend(finders::html::find_urls(&blob, base_url)?);
        } else if mimetype.contains("vcalendar")
            || mimetype.contains("icalendar")
            || memchr::memmem::find(&blob[..blob.len().min(256)], b"BEGIN:VCALENDAR").is_some()
        {
            urls.extend(finders::ical(&blob)?);
        } else if mimetype.contains("xml") {
            urls.extend(finders::xml(&blob)?);
        } else if memchr::memmem::find(&blob[..blob.len().min(1024)], b"%PDF-").is_some() {
            urls.extend(finders::pdf(&blob)?);
        } else if mimetype.contains("text") {
            let strings = if json_depth > 0 {
                json_strings(&blob)?
            } else {
                None
            };
            if let Some(strings) = strings {
                for string in &strings {
                    if string.contains('.') {
                        urls.extend(self.candidates(
                            string.as_bytes(),
                            base_url,
                            "text/plain",
                            domain_as_url,
                            json_depth - 1,
                            true,
                        )?);
                    }
                }
                urls.extend(base64_encoded_urls(strings.join("\n").as_bytes())?);
            } else if memchr::memmem::find(&blob, b"xmlns").is_some()
                && memchr::memmem::find(&blob, b"</").is_some()
            {
                urls.extend(finders::xml(&blob)?);
            } else if !json_string && is_maybe_csv(&blob) {
                urls.extend(finders::csv(&blob)?);
            } else if helpers::might_be_html(&blob) {
                urls.extend(finders::html::find_urls(&blob, "")?);
                urls.extend(finders::text::find_urls(&blob, domain_as_url)?);
            } else {
                urls.extend(finders::text::find_urls(&blob, domain_as_url)?);
            }
        } else {
            urls.extend(finders::data(&blob)?);
        }
        urls.extend(base64_encoded_urls(&blob)?);
        Ok(urls)
    }
}

/// `_distinct_urls`: one spelling of each URL found and of each URL found in those.
fn distinct_urls(urls: Vec<String>, domain_as_url: bool) -> PyResult<BTreeSet<String>> {
    let found = UrlList::from_values(urls.iter().map(String::as_str)).distinct_values()?;
    let expanded =
        UrlList::from_values(found.iter().map(String::as_str)).get_all_urls(domain_as_url)?;
    UrlList::from_values(expanded.iter().map(String::as_str)).distinct_values()
}

/// `find_urls_in_text(blob, domain_as_url)`: a blob known to be plain text.
pub fn find_urls_in_text(blob: &[u8], domain_as_url: bool) -> PyResult<BTreeSet<String>> {
    let mut urls: Vec<String> = finders::text::find_urls(blob, domain_as_url)?
        .into_iter()
        .collect();
    urls.extend(base64_encoded_urls(blob)?);
    distinct_urls(urls, domain_as_url)
}

/// `is_url(url)`.
pub fn is_url(url: &str) -> PyResult<bool> {
    Url::new(url).is_url()
}

#[cfg(test)]
mod tests;
