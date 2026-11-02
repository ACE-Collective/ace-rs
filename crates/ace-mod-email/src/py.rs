//! What ace3's email module gets from Python's `email` package, reproduced so the port reads
//! headers and addresses the same way.
//!
//! ace3 parses with `email.parser.BytesParser` under the `compat32` policy and reads headers with
//! `decode_rfc2822` (`saq/email.py`), `email.utils.parseaddr` and `getaddresses`. Each of those
//! has quirks that decide what lands in the details and which observables are added, so this
//! module follows Python 3.14's code (`email/feedparser.py`, `email/_policybase.py`,
//! `email/header.py`, `email/_parseaddr.py`, `email/utils.py`) rather than RFC 5322.

use std::sync::LazyLock;

use regex::Regex;

/// A header as compat32 stores it: the name as written and the value with leading whitespace and
/// the final line break removed. Folded lines keep their line breaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHeader {
    pub name: String,
    pub value: Vec<u8>,
}

/// A header value as `Message.__getitem__` returns it under compat32: a string, or, when the
/// value holds bytes outside ASCII, a `Header` in the unknown-8bit charset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderValue {
    Text(String),
    EightBit(Vec<u8>),
}

impl HeaderValue {
    fn from_bytes(value: &[u8]) -> Self {
        if value.is_ascii() {
            HeaderValue::Text(String::from_utf8_lossy(value).into_owned())
        } else {
            HeaderValue::EightBit(value.to_vec())
        }
    }

    /// `str(value)`: an unknown-8bit `Header` prints its bytes decoded as ASCII, each other byte
    /// replaced (`Header.__str__`).
    pub fn to_str(&self) -> String {
        match self {
            HeaderValue::Text(text) => text.clone(),
            HeaderValue::EightBit(bytes) => bytes
                .iter()
                .map(|&b| if b.is_ascii() { b as char } else { '\u{fffd}' })
                .collect(),
        }
    }
}

/// The header block of one message or MIME part, read the way `email.feedparser` reads it.
#[derive(Debug, Clone, Default)]
pub struct Headers {
    pub headers: Vec<RawHeader>,
    /// Where the body starts in the bytes the headers came from.
    pub body_offset: usize,
}

static HEADER_LINE: LazyLock<Regex> = LazyLock::new(|| {
    // feedparser's headerRE: `From `, a field name and a colon (the name may be empty), or a
    // continuation
    Regex::new(r"^(?:From |[\x21-\x39\x3b-\x7e]*:|[\t ])").expect("valid regex")
});

/// Splits `raw` into lines the way feedparser does: on `\r\n`, `\r` or `\n`, keeping each line's
/// ending.
fn lines(raw: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'\r' if raw.get(i + 1) == Some(&b'\n') => {
                lines.push(&raw[start..i + 2]);
                i += 2;
                start = i;
            }
            b'\r' | b'\n' => {
                lines.push(&raw[start..=i]);
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < raw.len() {
        lines.push(&raw[start..]);
    }
    lines
}

fn is_line_break(line: &[u8]) -> bool {
    matches!(line, b"\r\n" | b"\r" | b"\n")
}

/// Reads the header block at the start of `raw` (`FeedParser._parsegen` and `_parse_headers`
/// under compat32).
pub fn parse_headers(raw: &[u8]) -> Headers {
    let mut block: Vec<&[u8]> = Vec::new();
    let mut offset = 0;
    for line in lines(raw) {
        // matched as latin-1 text, which is what the regex sees of a surrogate-escaped line
        let text: String = line.iter().map(|&b| b as char).collect();
        if !HEADER_LINE.is_match(&text) {
            if is_line_break(line) {
                offset += line.len();
            }
            break;
        }
        block.push(line);
        offset += line.len();
    }

    let mut headers = Vec::new();
    let mut current: Vec<&[u8]> = Vec::new();
    let count = block.len();
    for (index, line) in block.into_iter().enumerate() {
        if line.first().is_some_and(|c| *c == b' ' || *c == b'\t') {
            // a continuation; one before any header is a defect and ignored
            if !current.is_empty() {
                current.push(line);
            }
            continue;
        }
        if !current.is_empty() {
            headers.push(source_parse(&current));
            current.clear();
        }
        if line.starts_with(b"From ") {
            if index == count - 1 && index != 0 {
                // probably the first line of the body: the body starts here
                offset -= line.len();
                break;
            }
            // the unix-from line, or a misplaced one; neither is a header
            continue;
        }
        match line.iter().position(|&c| c == b':') {
            // a line that starts with a colon has no name and is dropped
            Some(0) | None => continue,
            Some(_) => current.push(line),
        }
    }
    if !current.is_empty() {
        headers.push(source_parse(&current));
    }
    Headers {
        headers,
        body_offset: offset,
    }
}

/// compat32's `header_source_parse`.
fn source_parse(lines: &[&[u8]]) -> RawHeader {
    let first = lines[0];
    let colon = first.iter().position(|&c| c == b':').unwrap_or(first.len());
    let name: String = first[..colon].iter().map(|&b| b as char).collect();
    let mut value: Vec<u8> = first.get(colon + 1..).unwrap_or_default().to_vec();
    for line in &lines[1..] {
        value.extend_from_slice(line);
    }
    let start = value
        .iter()
        .position(|c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(value.len());
    let mut end = value.len();
    while end > start && matches!(value[end - 1], b'\r' | b'\n') {
        end -= 1;
    }
    RawHeader {
        name,
        value: value[start..end].to_vec(),
    }
}

impl Headers {
    /// `msg[name]`: the first header with this name, ignoring case.
    pub fn get(&self, name: &str) -> Option<HeaderValue> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| HeaderValue::from_bytes(&h.value))
    }

    /// `msg.get_all(name)`.
    pub fn get_all(&self, name: &str) -> Vec<HeaderValue> {
        self.headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| HeaderValue::from_bytes(&h.value))
            .collect()
    }

    /// `name in msg`.
    pub fn contains(&self, name: &str) -> bool {
        self.headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case(name))
    }

    /// `msg.items()`.
    pub fn items(&self) -> impl Iterator<Item = (&str, HeaderValue)> {
        self.headers
            .iter()
            .map(|h| (h.name.as_str(), HeaderValue::from_bytes(&h.value)))
    }

    /// `decode_rfc2822(msg[name])`, or None when the header is missing.
    pub fn decoded(&self, name: &str) -> Option<String> {
        self.get(name).map(|value| decode_rfc2822(&value))
    }

    /// `get_address_list(msg, name)` in `saq/modules/email/rfc822.py`: the address of each entry
    /// of every header with this name.
    pub fn address_list(&self, name: &str) -> Vec<String> {
        let values: Vec<String> = self.get_all(name).iter().map(decode_rfc2822).collect();
        getaddresses(&values).into_iter().map(|(_, a)| a).collect()
    }

    /// `msg.get_content_type()`, with `default` for a part without a Content-Type.
    pub fn content_type(&self, default: &str) -> String {
        let Some(value) = self.get("content-type") else {
            return default.to_owned();
        };
        let text = value.to_str();
        let ctype = text
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        if ctype.matches('/').count() != 1 {
            return "text/plain".to_owned();
        }
        ctype
    }

    /// `msg.get_param(param, header=header)`, unquoted; None when the header or the parameter
    /// isn't there.
    pub fn get_param(&self, param: &str, header: &str) -> Option<Param> {
        let value = self.get(header)?.to_str();
        params(&value)
            .into_iter()
            .find(|(k, _)| k.to_lowercase() == param.to_lowercase())
            .map(|(_, v)| match v {
                Param::Text(text) => Param::Text(unquote(&text)),
                Param::Encoded {
                    charset,
                    language,
                    value,
                } => Param::Encoded {
                    charset,
                    language,
                    value: unquote(&value),
                },
            })
    }

    /// `msg.get_content_charset()`, lowercased.
    pub fn content_charset(&self) -> Option<String> {
        let charset = match self.get_param("charset", "content-type")? {
            Param::Text(text) => text,
            Param::Encoded { charset, value, .. } => {
                let bytes = raw_unicode_escape(&value);
                let charset = charset.unwrap_or_else(|| "us-ascii".to_owned());
                decode_charset_strict(&bytes, &charset).unwrap_or(value)
            }
        };
        charset.is_ascii().then(|| charset.to_lowercase())
    }

    /// `msg.get_filename()`: the Content-Disposition's `filename`, else the Content-Type's
    /// `name`, with RFC 2231 encoding undone.
    pub fn filename(&self) -> Option<String> {
        let param = self
            .get_param("filename", "content-disposition")
            .or_else(|| self.get_param("name", "content-type"))?;
        Some(py_strip(&collapse_rfc2231_value(param)).to_owned())
    }
}

/// A parameter's value: plain text, or RFC 2231 text with its charset and language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Param {
    Text(String),
    Encoded {
        charset: Option<String>,
        language: Option<String>,
        value: String,
    },
}

/// `email.message._parseparam`: the parts of a structured header split on the semicolons that
/// aren't inside quotes, each `name=value` with the name lowercased.
fn parse_param_parts(value: &str) -> Vec<String> {
    let mut s: String = format!(";{value}");
    let mut parts = Vec::new();
    while s.starts_with(';') {
        s.remove(0);
        let quotes_before = |end: usize| {
            let head = &s[..end];
            head.matches('"').count() - head.matches("\\\"").count()
        };
        let mut end = s.find(';');
        while let Some(e) = end {
            if e > 0 && quotes_before(e) % 2 == 1 {
                end = s[e + 1..].find(';').map(|n| n + e + 1);
            } else {
                break;
            }
        }
        let end = end.unwrap_or(s.len());
        let mut part = s[..end].to_owned();
        if let Some(eq) = part.find('=') {
            part = format!(
                "{}={}",
                py_strip(&part[..eq]).to_lowercase(),
                py_strip(&part[eq + 1..])
            );
        }
        parts.push(py_strip(&part).to_owned());
        s = s[end..].to_owned();
    }
    parts
}

/// `_get_params_preserve` and `email.utils.decode_params`: every parameter, the first being the
/// header's main value, with RFC 2231 continuations joined and decoded.
fn params(value: &str) -> Vec<(String, Param)> {
    static CONTINUATION: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^(?P<name>[A-Za-z0-9_]+)\*(?:(?P<num>[0-9]+)\*?)?$").expect("valid regex")
    });
    let raw: Vec<(String, String)> = parse_param_parts(value)
        .into_iter()
        .map(|p| match p.split_once('=') {
            Some((name, val)) => (py_strip(name).to_owned(), py_strip(val).to_owned()),
            None => (py_strip(&p).to_owned(), String::new()),
        })
        .collect();
    let Some((first, rest)) = raw.split_first() else {
        return Vec::new();
    };
    let mut out = vec![(first.0.clone(), Param::Text(first.1.clone()))];
    // name -> its pieces, in the order seen
    let mut continued: Vec<(String, Vec<Piece>)> = Vec::new();
    for (name, value) in rest {
        let encoded = name.ends_with('*');
        let value = unquote(value);
        match CONTINUATION.captures(name) {
            Some(caps) => {
                let base = caps["name"].to_owned();
                let num = caps.name("num").and_then(|n| n.as_str().parse().ok());
                match continued.iter_mut().find(|(n, _)| *n == base) {
                    Some((_, list)) => list.push((num, value, encoded)),
                    None => continued.push((base, vec![(num, value, encoded)])),
                }
            }
            None => out.push((name.clone(), Param::Text(format!("\"{}\"", quote(&value))))),
        }
    }
    for (name, mut parts) in continued {
        if parts.iter().any(|p| p.0 == Some(0)) {
            parts.retain(|p| p.0.is_some());
        } else {
            for p in &mut parts {
                p.0 = Some(p.0.unwrap_or(0));
            }
        }
        parts.sort_by_key(|p| p.0);
        let mut extended = false;
        let mut joined = String::new();
        for (_, text, encoded) in parts {
            if encoded {
                joined.push_str(&percent_decode_latin1(&text));
                extended = true;
            } else {
                joined.push_str(&text);
            }
        }
        let joined = quote(&joined);
        if extended {
            let pieces: Vec<&str> = joined.splitn(3, '\'').collect();
            if let [charset, language, text] = pieces.as_slice() {
                out.push((
                    name,
                    Param::Encoded {
                        charset: Some((*charset).to_owned()).filter(|c| !c.is_empty()),
                        language: Some((*language).to_owned()).filter(|l| !l.is_empty()),
                        value: format!("\"{text}\""),
                    },
                ));
            } else {
                out.push((
                    name,
                    Param::Encoded {
                        charset: None,
                        language: None,
                        value: format!("\"{joined}\""),
                    },
                ));
            }
        } else {
            out.push((name, Param::Text(format!("\"{joined}\""))));
        }
    }
    out
}

/// One RFC 2231 piece of a parameter: its number, its text, and whether it is %-encoded.
type Piece = (Option<u32>, String, bool);

/// `urllib.parse.unquote(text, encoding="latin-1")`.
fn percent_decode_latin1(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .filter(|_| bytes[i] == b'%')
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        match hex {
            Some(byte) => {
                out.push(byte as char);
                i += 3;
            }
            None => {
                let c = text[i..].chars().next().unwrap_or_default();
                out.push(c);
                i += c.len_utf8();
            }
        }
    }
    out
}

/// `email.utils.quote`.
fn quote(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

/// `email.utils.unquote`.
pub fn unquote(text: &str) -> String {
    if text.chars().count() > 1 {
        if text.starts_with('"') && text.ends_with('"') {
            return text[1..text.len() - 1]
                .replace("\\\\", "\\")
                .replace("\\\"", "\"");
        }
        if text.starts_with('<') && text.ends_with('>') {
            return text[1..text.len() - 1].to_owned();
        }
    }
    text.to_owned()
}

/// `email.utils.collapse_rfc2231_value`.
fn collapse_rfc2231_value(param: Param) -> String {
    match param {
        Param::Text(text) => unquote(&text),
        Param::Encoded { charset, value, .. } => {
            let bytes = raw_unicode_escape(&value);
            let charset = charset.unwrap_or_else(|| "us-ascii".to_owned());
            decode_charset_replace(&bytes, &charset).unwrap_or_else(|| unquote(&value))
        }
    }
}

/// `str(email.header.make_header(email.header.decode_header(text)))`, as ace3 decodes an
/// attachment's name, or None where Python raises (an unknown charset or bytes that don't
/// decode), in which case ace3 keeps the name as it was.
pub fn make_header_str(text: &str) -> Option<String> {
    if !ENCODED_WORD.is_match(text) {
        return Some(text.to_owned());
    }
    // Header.append: each chunk decoded strictly with its charset, plain text as ASCII
    let mut chunks: Vec<(String, String)> = Vec::new();
    for (bytes, charset) in decode_header(text) {
        let charset = normalize_charset(charset.as_deref().unwrap_or("us-ascii"));
        let text = decode_charset_strict(&bytes, &charset)?;
        // Header._normalize joins neighbours in the same charset with a space
        match chunks.last_mut() {
            Some((last, last_charset)) if *last_charset == charset => {
                last.push(' ');
                last.push_str(&text);
            }
            _ => chunks.push((text, charset)),
        }
    }
    // Header.__str__ puts a space where an encoded chunk meets a plain one
    let nonctext = |c: Option<char>| c.is_some_and(|c| c.is_whitespace() || "()\\".contains(c));
    let plain = |charset: Option<&str>| matches!(charset, None | Some("us-ascii"));
    let mut out = String::new();
    let mut started = false;
    let mut last_charset: Option<String> = None;
    let mut last_space = false;
    for (text, charset) in chunks {
        let mut next_charset = Some(charset);
        if started {
            let has_space = nonctext(text.chars().next());
            if !plain(last_charset.as_deref()) {
                if plain(next_charset.as_deref()) && !has_space {
                    out.push(' ');
                    next_charset = None;
                }
            } else if !plain(next_charset.as_deref()) && !last_space {
                out.push(' ');
            }
        }
        last_space = nonctext(text.chars().last());
        last_charset = next_charset;
        out.push_str(&text);
        started = true;
    }
    Some(out)
}

/// `email.charset.Charset`'s name for a charset, as far as comparing two of them goes.
fn normalize_charset(charset: &str) -> String {
    let charset = charset.to_lowercase();
    match charset.as_str() {
        "ascii" => "us-ascii".to_owned(),
        "utf8" => "utf-8".to_owned(),
        "latin-1" | "latin_1" | "latin1" => "iso-8859-1".to_owned(),
        _ => charset,
    }
}

static ENCODED_WORD: LazyLock<Regex> = LazyLock::new(|| {
    // email.header.ecre
    Regex::new(r"=\?([^?]*?)\?([qQbB])\?(.*?)\?=").expect("valid regex")
});

/// `decode_rfc2822` in `saq/email.py`: `email.header.decode_header`, each part decoded with its
/// charset ignoring errors, then joined.
pub fn decode_rfc2822(value: &HeaderValue) -> String {
    match value {
        // decode_header gives the bytes back in the unknown-8bit charset, which isn't a Python
        // codec, so decode_rfc2822 falls back to UTF-8 and drops what doesn't decode
        HeaderValue::EightBit(bytes) => utf8_ignore(bytes),
        HeaderValue::Text(text) => decode_header(text)
            .into_iter()
            .map(|(bytes, charset)| match charset {
                None => utf8_ignore(&bytes),
                Some(charset) => {
                    decode_charset(&bytes, &charset).unwrap_or_else(|| utf8_ignore(&bytes))
                }
            })
            .collect(),
    }
}

/// `decode_rfc2822` of a plain string.
pub fn decode_str(text: &str) -> String {
    decode_rfc2822(&HeaderValue::Text(text.to_owned()))
}

/// `email.header.decode_header` of a string: (bytes, charset) chunks, charset None for text
/// that wasn't encoded.
fn decode_header(header: &str) -> Vec<(Vec<u8>, Option<String>)> {
    if !ENCODED_WORD.is_match(header) {
        return vec![(header.as_bytes().to_vec(), None)];
    }
    // (text, encoding, charset); encoding None for unencoded text
    let mut words: Vec<(String, Option<char>, Option<String>)> = Vec::new();
    for line in str_splitlines(header) {
        let mut first = true;
        let mut last = 0;
        let push_unencoded = |text: &str, first: &mut bool, words: &mut Vec<_>| {
            let text = if *first {
                *first = false;
                text.trim_start()
            } else {
                text
            };
            if !text.is_empty() {
                words.push((text.to_owned(), None, None));
            }
        };
        for caps in ENCODED_WORD.captures_iter(line) {
            let whole = caps.get(0).expect("group 0");
            push_unencoded(&line[last..whole.start()], &mut first, &mut words);
            let charset = caps[1].to_lowercase();
            let encoding = caps[2].to_ascii_lowercase().chars().next();
            words.push((caps[3].to_owned(), encoding, Some(charset)));
            last = whole.end();
        }
        push_unencoded(&line[last..], &mut first, &mut words);
    }
    // drop whitespace between two encoded words
    let mut drop = Vec::new();
    for n in 2..words.len() {
        if words[n].1.is_some() && words[n - 2].1.is_some() && is_py_space(&words[n - 1].0) {
            drop.push(n - 1);
        }
    }
    for d in drop.into_iter().rev() {
        words.remove(d);
    }

    let mut collapsed: Vec<(Vec<u8>, Option<String>)> = Vec::new();
    for (text, encoding, charset) in words {
        let word: Vec<u8> = match encoding {
            None => raw_unicode_escape(&text),
            Some('q') => header_decode_q(&text),
            Some(_) => {
                let mut encoded = text.clone();
                let pad = encoded.len() % 4;
                if pad != 0 {
                    encoded.push_str(&"==="[..4 - pad]);
                }
                a2b_base64(&encoded)
            }
        };
        match collapsed.last_mut() {
            Some((last, last_charset)) if *last_charset == charset => {
                if charset.is_none() {
                    last.push(b' ');
                }
                last.extend_from_slice(&word);
            }
            _ => collapsed.push((word, charset)),
        }
    }
    collapsed
}

/// `str.isspace()` of a non-empty string.
fn is_py_space(text: &str) -> bool {
    !text.is_empty() && text.chars().all(char::is_whitespace)
}

/// `str.splitlines()`: splits on the line boundaries Python's str knows.
fn str_splitlines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let is_break = matches!(
            c,
            '\n' | '\r'
                | '\u{0b}'
                | '\u{0c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if is_break {
            out.push(&text[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r'
                && let Some((_, '\n')) = chars.peek()
            {
                chars.next();
                end += 1;
            }
            start = end;
        }
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

/// `bytes(text, 'raw-unicode-escape')`.
fn raw_unicode_escape(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    for c in text.chars() {
        let code = c as u32;
        if code < 0x100 {
            out.push(code as u8);
        } else if code < 0x10000 {
            out.extend_from_slice(format!("\\u{code:04x}").as_bytes());
        } else {
            out.extend_from_slice(format!("\\U{code:08x}").as_bytes());
        }
    }
    out
}

/// `email.quoprimime.header_decode`: `_` is a space and `=XX` a byte.
fn header_decode_q(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .filter(|pair| pair.iter().all(u8::is_ascii_hexdigit))
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        match (bytes[i], hex) {
            (b'=', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (b'_', _) => {
                out.push(b' ');
                i += 1;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    out
}

/// `binascii.a2b_base64` in its default, non-strict mode: characters outside the alphabet are
/// skipped, and a complete pad sequence ends the input. Python raises when the data ends inside
/// a quantum, which makes ace3's `decode_header` raise; this keeps the bytes decoded so far.
pub fn a2b_base64(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut quad_pos = 0;
    let mut pads = 0;
    let mut left = 0u32;
    for &c in text.as_bytes() {
        if c == b'=' {
            pads += 1;
            if quad_pos >= 2 && quad_pos + pads >= 4 {
                break;
            }
            continue;
        }
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        pads = 0;
        left = (left << 6) | u32::from(value);
        quad_pos += 1;
        match quad_pos {
            2 => out.push((left >> 4) as u8),
            3 => out.push((left >> 2) as u8),
            4 => {
                out.push(left as u8);
                quad_pos = 0;
                left = 0;
            }
            _ => {}
        }
        left &= 0xff;
    }
    out
}

/// `bytes.decode('utf-8', errors='ignore')`.
pub fn utf8_ignore(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
    }
    out
}

/// `bytes.decode(charset, errors='ignore')`, or None when Python has no codec by that name.
pub fn decode_charset(bytes: &[u8], charset: &str) -> Option<String> {
    let label = charset.trim().to_ascii_lowercase().replace('_', "-");
    match label.as_str() {
        "utf-8" | "utf8" | "u8" | "utf" | "cp65001" => Some(utf8_ignore(bytes)),
        "us-ascii" | "ascii" | "646" | "us" => Some(
            bytes
                .iter()
                .filter(|b| b.is_ascii())
                .map(|&b| b as char)
                .collect(),
        ),
        "iso-8859-1" | "iso8859-1" | "latin-1" | "latin1" | "l1" | "8859" | "cp819"
        | "iso-ir-100" => Some(bytes.iter().map(|&b| b as char).collect()),
        _ => {
            let encoding = encoding_rs::Encoding::for_label(label.as_bytes())?;
            let (text, _) = encoding.decode_without_bom_handling(bytes);
            // errors='ignore' drops what doesn't decode instead of replacing it
            Some(text.chars().filter(|&c| c != '\u{fffd}').collect())
        }
    }
}

/// `bytes.decode(charset, errors='replace')`, or None when Python has no codec by that name.
pub fn decode_charset_replace(bytes: &[u8], charset: &str) -> Option<String> {
    let label = charset.trim().to_ascii_lowercase().replace('_', "-");
    match label.as_str() {
        "utf-8" | "utf8" | "u8" | "utf" | "cp65001" => {
            Some(String::from_utf8_lossy(bytes).into_owned())
        }
        "us-ascii" | "ascii" | "646" | "us" => Some(
            bytes
                .iter()
                .map(|&b| if b.is_ascii() { b as char } else { '\u{fffd}' })
                .collect(),
        ),
        "iso-8859-1" | "iso8859-1" | "latin-1" | "latin1" | "l1" | "8859" | "cp819"
        | "iso-ir-100" => Some(bytes.iter().map(|&b| b as char).collect()),
        _ => {
            let encoding = encoding_rs::Encoding::for_label(label.as_bytes())?;
            Some(encoding.decode_without_bom_handling(bytes).0.into_owned())
        }
    }
}

/// `bytes.decode(charset)` with strict errors: None when it fails or there's no such codec.
pub fn decode_charset_strict(bytes: &[u8], charset: &str) -> Option<String> {
    let label = charset.trim().to_ascii_lowercase().replace('_', "-");
    match label.as_str() {
        "utf-8" | "utf8" | "u8" | "utf" | "cp65001" => String::from_utf8(bytes.to_vec()).ok(),
        "us-ascii" | "ascii" | "646" | "us" => bytes
            .is_ascii()
            .then(|| bytes.iter().map(|&b| b as char).collect()),
        "iso-8859-1" | "iso8859-1" | "latin-1" | "latin1" | "l1" | "8859" | "cp819"
        | "iso-ir-100" => Some(bytes.iter().map(|&b| b as char).collect()),
        _ => {
            let encoding = encoding_rs::Encoding::for_label(label.as_bytes())?;
            encoding
                .decode_without_bom_handling_and_without_replacement(bytes)
                .map(|text| text.into_owned())
        }
    }
}

/// The address parser of `email._parseaddr.AddrlistClass`.
struct AddrList {
    field: Vec<char>,
    pos: usize,
    commentlist: Vec<String>,
}

const SPECIALS: &str = "()<>@,:;.\"[]";
const LWS: &str = " \t";
const CR: &str = "\r\n";

fn is_atomend(c: char) -> bool {
    SPECIALS.contains(c) || LWS.contains(c) || CR.contains(c)
}

fn is_phraseend(c: char) -> bool {
    c != '.' && is_atomend(c)
}

impl AddrList {
    fn new(field: &str) -> Self {
        AddrList {
            field: field.chars().collect(),
            pos: 0,
            commentlist: Vec::new(),
        }
    }

    fn at(&self) -> Option<char> {
        self.field.get(self.pos).copied()
    }

    fn gotonext(&mut self) -> String {
        let mut ws = String::new();
        while let Some(c) = self.at() {
            if " \t\n\r".contains(c) {
                if c != '\n' && c != '\r' {
                    ws.push(c);
                }
                self.pos += 1;
            } else if c == '(' {
                let comment = self.getcomment();
                self.commentlist.push(comment);
            } else {
                break;
            }
        }
        ws
    }

    fn getaddrlist(&mut self) -> Vec<(String, String)> {
        let mut result = Vec::new();
        while self.pos < self.field.len() {
            let ad = self.getaddress();
            if ad.is_empty() {
                result.push((String::new(), String::new()));
            } else {
                result.extend(ad);
            }
        }
        result
    }

    fn getaddress(&mut self) -> Vec<(String, String)> {
        self.commentlist.clear();
        self.gotonext();

        let oldpos = self.pos;
        let oldcl = self.commentlist.clone();
        let plist = self.getphraselist();

        self.gotonext();
        let mut returnlist = Vec::new();

        match self.at() {
            None => {
                if let Some(first) = plist.first() {
                    returnlist = vec![(self.commentlist.join(" "), first.clone())];
                }
            }
            Some(c) if c == '.' || c == '@' => {
                self.pos = oldpos;
                self.commentlist = oldcl;
                let addrspec = self.getaddrspec();
                returnlist = vec![(self.commentlist.join(" "), addrspec)];
            }
            Some(':') => {
                self.pos += 1;
                while self.pos < self.field.len() {
                    self.gotonext();
                    if self.at() == Some(';') {
                        self.pos += 1;
                        break;
                    }
                    returnlist.extend(self.getaddress());
                }
            }
            Some('<') => {
                let routeaddr = self.getrouteaddr();
                let name = if self.commentlist.is_empty() {
                    plist.join(" ")
                } else {
                    format!("{} ({})", plist.join(" "), self.commentlist.join(" "))
                };
                returnlist = vec![(name, routeaddr)];
            }
            Some(c) => {
                if let Some(first) = plist.first() {
                    returnlist = vec![(self.commentlist.join(" "), first.clone())];
                } else if SPECIALS.contains(c) {
                    self.pos += 1;
                }
            }
        }

        self.gotonext();
        if self.at() == Some(',') {
            self.pos += 1;
        }
        returnlist
    }

    fn getrouteaddr(&mut self) -> String {
        if self.at() != Some('<') {
            return String::new();
        }
        let mut expectroute = false;
        self.pos += 1;
        self.gotonext();
        let mut adlist = String::new();
        while let Some(c) = self.at() {
            if expectroute {
                self.getdomain();
                expectroute = false;
            } else if c == '>' {
                self.pos += 1;
                break;
            } else if c == '@' {
                self.pos += 1;
                expectroute = true;
            } else if c == ':' {
                self.pos += 1;
            } else {
                adlist = self.getaddrspec();
                self.pos += 1;
                break;
            }
            self.gotonext();
        }
        adlist
    }

    fn getaddrspec(&mut self) -> String {
        let mut aslist: Vec<String> = Vec::new();
        self.gotonext();
        while let Some(c) = self.at() {
            let mut preserve_ws = true;
            if c == '.' {
                if aslist.last().is_some_and(|w| w.trim().is_empty()) {
                    aslist.pop();
                }
                aslist.push(".".to_owned());
                self.pos += 1;
                preserve_ws = false;
            } else if c == '"' {
                let quoted = self.getquote();
                aslist.push(format!(
                    "\"{}\"",
                    quoted.replace('\\', "\\\\").replace('"', "\\\"")
                ));
            } else if is_atomend(c) {
                if aslist.last().is_some_and(|w| w.trim().is_empty()) {
                    aslist.pop();
                }
                break;
            } else {
                let atom = self.getatom(false);
                aslist.push(atom);
            }
            let ws = self.gotonext();
            if preserve_ws && !ws.is_empty() {
                aslist.push(ws);
            }
        }

        if self.at() != Some('@') {
            return aslist.concat();
        }
        aslist.push("@".to_owned());
        self.pos += 1;
        self.gotonext();
        let domain = self.getdomain();
        if domain.is_empty() {
            return String::new();
        }
        aslist.concat() + &domain
    }

    fn getdomain(&mut self) -> String {
        let mut sdlist: Vec<String> = Vec::new();
        while let Some(c) = self.at() {
            if LWS.contains(c) {
                self.pos += 1;
            } else if c == '(' {
                let comment = self.getcomment();
                self.commentlist.push(comment);
            } else if c == '[' {
                let literal = self.getdomainliteral();
                sdlist.push(literal);
            } else if c == '.' {
                self.pos += 1;
                sdlist.push(".".to_owned());
            } else if c == '@' {
                return String::new();
            } else if is_atomend(c) {
                break;
            } else {
                let atom = self.getatom(false);
                sdlist.push(atom);
            }
        }
        sdlist.concat()
    }

    fn getdelimited(&mut self, beginchar: char, endchars: &str, allowcomments: bool) -> String {
        if self.at() != Some(beginchar) {
            return String::new();
        }
        let mut slist = String::new();
        let mut quote = false;
        self.pos += 1;
        while let Some(c) = self.at() {
            if quote {
                slist.push(c);
                quote = false;
            } else if endchars.contains(c) {
                self.pos += 1;
                break;
            } else if allowcomments && c == '(' {
                let comment = self.getcomment();
                slist.push_str(&comment);
                continue;
            } else if c == '\\' {
                quote = true;
            } else {
                slist.push(c);
            }
            self.pos += 1;
        }
        slist
    }

    fn getquote(&mut self) -> String {
        self.getdelimited('"', "\"\r", false)
    }

    fn getcomment(&mut self) -> String {
        self.getdelimited('(', ")\r", true)
    }

    fn getdomainliteral(&mut self) -> String {
        format!("[{}]", self.getdelimited('[', "]\r", false))
    }

    fn getatom(&mut self, phrase: bool) -> String {
        let mut atom = String::new();
        while let Some(c) = self.at() {
            let end = if phrase {
                is_phraseend(c)
            } else {
                is_atomend(c)
            };
            if end {
                break;
            }
            atom.push(c);
            self.pos += 1;
        }
        atom
    }

    fn getphraselist(&mut self) -> Vec<String> {
        let mut plist = Vec::new();
        while let Some(c) = self.at() {
            if " \t\r\n".contains(c) {
                self.pos += 1;
            } else if c == '"' {
                plist.push(self.getquote());
            } else if c == '(' {
                let comment = self.getcomment();
                self.commentlist.push(comment);
            } else if is_phraseend(c) {
                break;
            } else {
                plist.push(self.getatom(true));
            }
        }
        plist
    }
}

fn address_list(field: &str) -> Vec<(String, String)> {
    if field.is_empty() {
        return Vec::new();
    }
    AddrList::new(field).getaddrlist()
}

/// `email.utils._iter_escaped_chars`: (position, char) pairs, a backslash escape as one item.
fn iter_escaped_chars(addr: &str) -> Vec<(usize, String)> {
    let chars: Vec<char> = addr.chars().collect();
    let mut out = Vec::new();
    let mut escape = false;
    let mut last = 0;
    for (pos, &ch) in chars.iter().enumerate() {
        last = pos;
        if escape {
            out.push((pos, format!("\\{ch}")));
            escape = false;
        } else if ch == '\\' {
            escape = true;
        } else {
            out.push((pos, ch.to_string()));
        }
    }
    if escape {
        out.push((last, "\\".to_owned()));
    }
    out
}

/// `email.utils._strip_quoted_realnames`.
fn strip_quoted_realnames(addr: &str) -> String {
    if !addr.contains('"') {
        return addr.to_owned();
    }
    let chars: Vec<char> = addr.chars().collect();
    let mut start = 0;
    let mut open_pos: Option<usize> = None;
    let mut result = String::new();
    for (pos, ch) in iter_escaped_chars(addr) {
        if ch == "\"" {
            match open_pos {
                None => open_pos = Some(pos),
                Some(open) => {
                    if start != open {
                        result.extend(&chars[start..open]);
                    }
                    start = pos + 1;
                    open_pos = None;
                }
            }
        }
    }
    if start < chars.len() {
        result.extend(&chars[start..]);
    }
    result
}

/// `email.utils._check_parenthesis`.
fn check_parenthesis(addr: &str) -> bool {
    let addr = strip_quoted_realnames(addr);
    let mut opens = 0i64;
    for (_, ch) in iter_escaped_chars(&addr) {
        if ch == "(" {
            opens += 1;
        } else if ch == ")" {
            opens -= 1;
            if opens < 0 {
                return false;
            }
        }
    }
    opens == 0
}

fn pre_parse_validation(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|v| {
            if check_parenthesis(v) {
                v.clone()
            } else {
                "('', '')".to_owned()
            }
        })
        .collect()
}

fn post_parse_validation(parsed: Vec<(String, String)>) -> Vec<(String, String)> {
    parsed
        .into_iter()
        .map(|v| {
            if v.1.contains('[') {
                (String::new(), String::new())
            } else {
                v
            }
        })
        .collect()
}

/// `email.utils.getaddresses(values)` with its default `strict=True`.
pub fn getaddresses(values: &[String]) -> Vec<(String, String)> {
    let values = pre_parse_validation(values);
    let joined = values.join(", ");
    let result = post_parse_validation(address_list(&joined));
    let expected: usize = values
        .iter()
        .map(|v| 1 + strip_quoted_realnames(v).matches(',').count())
        .sum();
    if result.len() != expected {
        return vec![(String::new(), String::new())];
    }
    result
}

/// `email.utils.parseaddr(addr)` with its default `strict=True`.
pub fn parseaddr(addr: &str) -> (String, String) {
    let addr = &pre_parse_validation(&[addr.to_owned()])[0];
    let addrs = post_parse_validation(address_list(addr));
    if addrs.len() != 1 {
        return (String::new(), String::new());
    }
    addrs.into_iter().next().unwrap_or_default()
}

/// `normalize_email_address` in `saq/email.py`.
pub fn normalize_email_address(email_address: &str) -> Option<String> {
    let (_, mut address) = parseaddr(email_address);
    if address.is_empty() {
        // known cases the standard library gets wrong, like <<person@example.com>>
        let mut fixed = email_address.to_owned();
        while !fixed.is_empty() && fixed.contains("<<") && fixed.contains(">>") {
            fixed = fixed.replace("<<", "<").replace(">>", ">");
        }
        address = parseaddr(&fixed).1;
        if address.is_empty() {
            return None;
        }
    }
    let address = py_strip(&address)
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_owned();
    if address.is_empty() {
        return None;
    }
    Some(address.to_lowercase())
}

/// `str.strip()`, which strips Unicode whitespace.
pub fn py_strip(text: &str) -> &str {
    text.trim_matches(char::is_whitespace)
}

/// `normalize_message_id` in `saq/email.py`.
pub fn normalize_message_id(message_id: &str) -> String {
    let mut id = py_strip(message_id).to_owned();
    if !id.starts_with('<') {
        id.insert(0, '<');
    }
    if !id.ends_with('>') {
        id.push('>');
    }
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(text: &str) -> String {
        text.to_owned()
    }

    #[test]
    fn headers_keep_folding_and_drop_the_final_line_break() {
        let raw = b"From sender@example.com Mon Jan 1 00:00:00 2024\nSubject: one\n two\r\nX-Empty:\nTo:  a@example.com\n\nbody\n";
        let headers = parse_headers(raw);
        let names: Vec<&str> = headers.headers.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["Subject", "X-Empty", "To"]);
        assert_eq!(headers.headers[0].value, b"one\n two");
        assert_eq!(headers.headers[1].value, b"");
        assert_eq!(headers.headers[2].value, b"a@example.com");
        assert_eq!(&raw[headers.body_offset..], b"body\n");
    }

    #[test]
    fn a_line_that_is_no_header_starts_the_body() {
        let raw = b"Subject: x\nnot a header\nmore\n";
        let headers = parse_headers(raw);
        assert_eq!(headers.headers.len(), 1);
        assert_eq!(&raw[headers.body_offset..], b"not a header\nmore\n");
    }

    #[test]
    fn eight_bit_headers_decode_as_utf8_dropping_errors() {
        let value = HeaderValue::from_bytes("caf\u{e9} ok".as_bytes());
        assert!(matches!(value, HeaderValue::EightBit(_)));
        assert_eq!(decode_rfc2822(&value), "caf\u{e9} ok");
        let latin1 = HeaderValue::from_bytes(b"caf\xe9 ok");
        assert_eq!(decode_rfc2822(&latin1), "caf ok");
    }

    #[test]
    fn encoded_words_decode_like_decode_header() {
        assert_eq!(decode_str("=?utf-8?q?caf=C3=A9_au_lait?="), "café au lait");
        assert_eq!(
            decode_str("=?UTF-8?B?Y2Fmw6k=?= =?UTF-8?B?IG5vaXI=?="),
            "café noir"
        );
        // whitespace between encoded words goes, around them it stays
        assert_eq!(decode_str("Re: =?utf-8?q?x?= y"), "Re: x y");
        // a folded encoded word loses the space before it, as in Python
        assert_eq!(decode_str("Hello\n =?utf-8?q?x?="), "Hellox");
        // base64 without padding is padded
        assert_eq!(decode_str("=?utf-8?b?Y2Fm?="), "caf");
        // an unknown charset falls back to UTF-8
        assert_eq!(decode_str("=?x-unknown?q?abc?="), "abc");
        assert_eq!(decode_str("plain text"), "plain text");
    }

    #[test]
    fn addresses_parse_like_email_utils() {
        assert_eq!(
            parseaddr("John Davison <unixfreak0037@gmail.com>"),
            (s("John Davison"), s("unixfreak0037@gmail.com"))
        );
        assert_eq!(parseaddr("a@b.com"), (s(""), s("a@b.com")));
        // two addresses in one: strict parsing refuses
        assert_eq!(parseaddr("a@b.com, c@d.com"), (s(""), s("")));
        assert_eq!(
            getaddresses(&[s("\"Doe, John\" <a@x.com>, b@x.com")]),
            vec![(s("Doe, John"), s("a@x.com")), (s(""), s("b@x.com"))]
        );
        assert_eq!(
            getaddresses(&[s("alice@example.com <bob@example.com>")]),
            vec![(s(""), s(""))]
        );
        assert_eq!(parseaddr("<a@[1.2.3.4]>"), (s(""), s("")));
        assert_eq!(parseaddr("a@malicious.org@important.com"), (s(""), s("")));
    }

    #[test]
    fn base64_decodes_like_binascii() {
        assert_eq!(a2b_base64("Y2Fm6SD//g=="), b"caf\xe9 \xff\xfe");
        // characters outside the alphabet are skipped
        assert_eq!(a2b_base64("Y2F\nm"), b"caf");
        // a complete pad sequence ends the input
        assert_eq!(a2b_base64("YQ==YWJj"), b"a");
        assert_eq!(a2b_base64("YW=Jj"), b"abc");
    }

    #[test]
    fn filenames_decode_like_get_filename_and_make_header() {
        let headers = parse_headers(
            b"Content-Type: application/octet-stream; name=\"fallback.bin\"\n\
Content-Disposition: attachment; filename*=utf-8''caf%C3%A9.txt\n\n",
        );
        assert_eq!(headers.filename(), Some(s("caf\u{e9}.txt")));
        let headers = parse_headers(
            b"Content-Disposition: attachment; filename*0=\"in\"; filename*1=\"voice.pdf\"\n\n",
        );
        assert_eq!(headers.filename(), Some(s("invoice.pdf")));
        let headers = parse_headers(b"Content-Type: text/plain; name=\"a; b.txt\"\n\n");
        assert_eq!(headers.filename(), Some(s("a; b.txt")));
        assert_eq!(
            parse_headers(b"Content-Type: text/plain\n\n").filename(),
            None
        );
        // a space where an encoded chunk meets a plain one, as Header.__str__ puts it
        assert_eq!(
            make_header_str("=?utf-8?b?SGVsbG8=?=__=?utf-8?b?V29ybGQ=?=.txt"),
            Some(s("Hello __ World .txt"))
        );
        assert_eq!(make_header_str("=?x-unknown?q?abc?="), None);
        assert_eq!(make_header_str("plain.txt"), Some(s("plain.txt")));
    }

    #[test]
    fn email_addresses_normalize_like_saq_email() {
        assert_eq!(
            normalize_email_address("John <John.Davison@Company.com>"),
            Some(s("john.davison@company.com"))
        );
        assert_eq!(
            normalize_email_address("<<person@example.com>>"),
            Some(s("person@example.com"))
        );
        assert_eq!(normalize_email_address("not an address"), Some(s("not")));
        assert_eq!(normalize_email_address(""), None);
        assert_eq!(normalize_message_id(" abc@x "), "<abc@x>");
    }
}
