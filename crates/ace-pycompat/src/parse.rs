//! `urllib.parse` of Python 3.14.10, on `str`.
//!
//! `urlsplit` strips leading C0 controls and spaces, removes every tab, CR and LF, takes a scheme
//! only when it starts with an ASCII letter and has only scheme characters, and raises `ValueError`
//! for unbalanced brackets, for a bracketed host that isn't an IPv6 address or an IPvFuture, and
//! for a netloc that NFKC normalization (Unicode 16) would give a `/`, `?`, `#`, `@` or `:`.
//! `unquote` decodes UTF-8 with errors="replace", one ASCII run at a time; `quote` encodes UTF-8.

use std::borrow::Cow;
use std::collections::HashMap;

use crate::PyErr;
use crate::ipaddress::{IpAddress, ip_address};
use crate::pystr::{decode_utf8_replace, lower};
use crate::repr::repr;
use crate::unicodedata::nfkc;

const USES_RELATIVE: &[&str] = &[
    "", "ftp", "http", "gopher", "nntp", "imap", "wais", "file", "https", "shttp", "mms",
    "prospero", "rtsp", "rtsps", "rtspu", "sftp", "svn", "svn+ssh", "ws", "wss",
];

const USES_NETLOC: &[&str] = &[
    "",
    "ftp",
    "http",
    "gopher",
    "nntp",
    "telnet",
    "imap",
    "wais",
    "file",
    "mms",
    "https",
    "shttp",
    "snews",
    "prospero",
    "rtsp",
    "rtsps",
    "rtspu",
    "rsync",
    "svn",
    "svn+ssh",
    "sftp",
    "nfs",
    "git",
    "git+ssh",
    "ws",
    "wss",
    "itms-services",
];

const USES_PARAMS: &[&str] = &[
    "", "ftp", "hdl", "prospero", "http", "imap", "https", "shttp", "rtsp", "rtsps", "rtspu",
    "sip", "sips", "mms", "sftp", "tel",
];

fn is_scheme_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')
}

fn is_c0_or_space(c: char) -> bool {
    c <= ' '
}

/// A `SplitResult`: `urlsplit`'s five parts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SplitResult {
    pub scheme: String,
    pub netloc: String,
    pub path: String,
    pub query: String,
    pub fragment: String,
}

/// A `ParseResult`: `urlparse`'s six parts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParseResult {
    pub scheme: String,
    pub netloc: String,
    pub path: String,
    pub params: String,
    pub query: String,
    pub fragment: String,
}

/// The netloc properties both result types have.
fn userinfo(netloc: &str) -> (Option<&str>, Option<&str>) {
    match netloc.rsplit_once('@') {
        Some((info, _)) => match info.split_once(':') {
            Some((user, password)) => (Some(user), Some(password)),
            None => (Some(info), None),
        },
        None => (None, None),
    }
}

fn hostinfo(netloc: &str) -> (&str, Option<&str>) {
    let hostinfo = netloc.rsplit_once('@').map_or(netloc, |(_, h)| h);
    let (hostname, port) = match hostinfo.split_once('[') {
        Some((_, bracketed)) => {
            let (hostname, rest) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            (hostname, rest.split_once(':').map_or("", |(_, p)| p))
        }
        None => hostinfo.split_once(':').unwrap_or((hostinfo, "")),
    };
    (hostname, (!port.is_empty()).then_some(port))
}

fn hostname(netloc: &str) -> Option<String> {
    let (host, _) = hostinfo(netloc);
    if host.is_empty() {
        return None;
    }
    // A scoped IPv6 address's zone isn't lowercased.
    Some(match host.split_once('%') {
        Some((h, zone)) => format!("{}%{zone}", lower(h)),
        None => lower(host).into_owned(),
    })
}

fn port(netloc: &str) -> Result<Option<u16>, PyErr> {
    let Some(port) = hostinfo(netloc).1 else {
        return Ok(None);
    };
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PyErr::value_error(format!(
            "Port could not be cast to integer value as {}",
            repr(port)
        )));
    }
    let digits = port.trim_start_matches('0');
    match digits.parse::<u32>() {
        Ok(v) if digits.len() <= 5 && v <= 65535 => Ok(Some(v as u16)),
        _ if digits.is_empty() => Ok(Some(0)),
        _ => Err(PyErr::value_error("Port out of range 0-65535")),
    }
}

macro_rules! netloc_properties {
    ($t:ty) => {
        impl $t {
            /// `.hostname`: lowercased, without brackets or port; the IPv6 zone keeps its case.
            pub fn hostname(&self) -> Option<String> {
                hostname(&self.netloc)
            }

            /// `.port`, which raises `ValueError` for a port that isn't ASCII digits or is over 65535.
            pub fn port(&self) -> Result<Option<u16>, PyErr> {
                port(&self.netloc)
            }

            /// `.username`.
            pub fn username(&self) -> Option<&str> {
                userinfo(&self.netloc).0
            }

            /// `.password`.
            pub fn password(&self) -> Option<&str> {
                userinfo(&self.netloc).1
            }
        }
    };
}

netloc_properties!(SplitResult);
netloc_properties!(ParseResult);

impl SplitResult {
    /// `.geturl()`.
    pub fn geturl(&self) -> String {
        urlunsplit(
            &self.scheme,
            &self.netloc,
            &self.path,
            &self.query,
            &self.fragment,
        )
    }
}

impl ParseResult {
    /// `.geturl()`.
    pub fn geturl(&self) -> String {
        urlunparse(
            &self.scheme,
            &self.netloc,
            &self.path,
            &self.params,
            &self.query,
            &self.fragment,
        )
    }
}

/// `_urlsplit`'s parts, with None where Python has None.
struct Parts {
    scheme: Option<String>,
    netloc: Option<String>,
    path: String,
    query: Option<String>,
    fragment: Option<String>,
}

fn remove_unsafe(s: &str) -> Cow<'_, str> {
    let bytes = s.as_bytes();
    let Some(first) = memchr::memchr3(b'\t', b'\r', b'\n', bytes) else {
        return Cow::Borrowed(s);
    };
    // the three are ASCII, so dropping their bytes keeps the rest whole UTF-8
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[..first]);
    let mut at = first + 1;
    while let Some(next) = memchr::memchr3(b'\t', b'\r', b'\n', &bytes[at..]) {
        out.extend_from_slice(&bytes[at..at + next]);
        at += next + 1;
    }
    out.extend_from_slice(&bytes[at..]);
    // SAFETY: only whole ASCII bytes were left out of valid UTF-8
    Cow::Owned(unsafe { String::from_utf8_unchecked(out) })
}

fn urlsplit_parts(url: &str, scheme: Option<&str>, allow_fragments: bool) -> Result<Parts, PyErr> {
    let url = remove_unsafe(url.trim_start_matches(is_c0_or_space));
    let mut scheme = scheme.map(|s| remove_unsafe(s.trim_matches(is_c0_or_space)).into_owned());
    let mut url: &str = &url;
    let mut netloc = None;
    let mut query = None;
    let mut fragment = None;
    if let Some(i) = url.find(':')
        && i > 0
        && url.as_bytes()[0].is_ascii_alphabetic()
        && url[..i].chars().all(is_scheme_char)
    {
        scheme = Some(url[..i].to_ascii_lowercase());
        url = &url[i + 1..];
    }
    if url.starts_with("//") {
        let rest = &url[2..];
        let delim = rest
            .bytes()
            .position(|b| matches!(b, b'/' | b'?' | b'#'))
            .unwrap_or(rest.len());
        let n = &rest[..delim];
        url = &rest[delim..];
        let open = n.contains('[');
        let close = n.contains(']');
        if open != close {
            return Err(PyErr::value_error("Invalid IPv6 URL"));
        }
        if open && close {
            check_bracketed_netloc(n)?;
        }
        netloc = Some(n.to_owned());
    }
    if allow_fragments && let Some((u, f)) = url.split_once('#') {
        fragment = Some(f.to_owned());
        url = u;
    }
    if let Some((u, q)) = url.split_once('?') {
        query = Some(q.to_owned());
        url = u;
    }
    if let Some(n) = &netloc {
        check_netloc(n)?;
    }
    Ok(Parts {
        scheme,
        netloc,
        path: url.to_owned(),
        query,
        fragment,
    })
}

fn check_netloc(netloc: &str) -> Result<(), PyErr> {
    if netloc.is_empty() || netloc.is_ascii() {
        return Ok(());
    }
    let n: String = netloc
        .chars()
        .filter(|c| !matches!(c, '@' | ':' | '#' | '?'))
        .collect();
    let netloc2 = nfkc(&n);
    if n == netloc2 {
        return Ok(());
    }
    if netloc2.contains(['/', '?', '#', '@', ':']) {
        return Err(PyErr::value_error(format!(
            "netloc '{netloc}' contains invalid characters under NFKC normalization"
        )));
    }
    Ok(())
}

fn check_bracketed_netloc(netloc: &str) -> Result<(), PyErr> {
    let hostname_and_port = netloc.rsplit_once('@').map_or(netloc, |(_, h)| h);
    let hostname = match hostname_and_port.split_once('[') {
        Some((before, bracketed)) => {
            if !before.is_empty() {
                return Err(PyErr::value_error("Invalid IPv6 URL"));
            }
            let (hostname, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            if !port.is_empty() && !port.starts_with(':') {
                return Err(PyErr::value_error("Invalid IPv6 URL"));
            }
            hostname
        }
        None => hostname_and_port
            .split_once(':')
            .map_or(hostname_and_port, |(h, _)| h),
    };
    check_bracketed_host(hostname)
}

fn check_bracketed_host(hostname: &str) -> Result<(), PyErr> {
    if hostname.starts_with(['v', 'V']) {
        // re.match(r"\A[vV][a-fA-F0-9]+\..+\z", hostname)
        let rest = &hostname[1..];
        let hex = rest.bytes().take_while(u8::is_ascii_hexdigit).count();
        let ok = hex > 0
            && rest[hex..].starts_with('.')
            && rest.len() > hex + 1
            && !rest[hex + 1..].contains('\n');
        if !ok {
            return Err(PyErr::value_error("IPvFuture address is invalid"));
        }
        Ok(())
    } else {
        match ip_address(hostname)? {
            IpAddress::V4(_) => Err(PyErr::value_error("An IPv4 address cannot be in brackets")),
            IpAddress::V6(_) => Ok(()),
        }
    }
}

/// What `urlsplit(url)` says of a URL's start, without copying its path: the scheme, the netloc
/// (None where there is no `//`) and whether the path is empty, with `urlsplit`'s ValueErrors.
/// For callers on long hostile strings that need no more, such as urlfinderlib's
/// `fix_possible_value`. `tests::head_agrees_with_urlsplit` holds it to `urlsplit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitHead {
    pub scheme: String,
    pub netloc: Option<String>,
    pub path_is_empty: bool,
}

fn is_unsafe(c: char) -> bool {
    matches!(c, '\t' | '\r' | '\n')
}

/// `urlsplit(url)`'s scheme, netloc and whether its path is empty.
pub fn urlsplit_head(url: &str) -> Result<SplitHead, PyErr> {
    let url = url.trim_start_matches(is_c0_or_space);
    // the scheme: the text before the first ':', with \t \r \n removed, if it's a scheme
    let mut scheme = String::new();
    let mut rest = url;
    let mut candidate = String::new();
    for (i, c) in url.char_indices() {
        if is_unsafe(c) {
            continue;
        }
        if c == ':' {
            if !candidate.is_empty() && candidate.as_bytes()[0].is_ascii_alphabetic() {
                scheme = candidate.to_ascii_lowercase();
                rest = &url[i + 1..];
            }
            break;
        }
        if !is_scheme_char(c) {
            break;
        }
        candidate.push(c);
    }
    // "//", with \t \r \n between
    let mut chars = rest.char_indices().filter(|(_, c)| !is_unsafe(*c));
    let mut netloc = None;
    let after = match (chars.next(), chars.next()) {
        (Some((_, '/')), Some((j, '/'))) => {
            let body = &rest[j + 1..];
            let mut n = String::new();
            let mut end = body.len();
            for (k, c) in body.char_indices() {
                if matches!(c, '/' | '?' | '#') {
                    end = k;
                    break;
                }
                if !is_unsafe(c) {
                    n.push(c);
                }
            }
            let open = n.contains('[');
            let close = n.contains(']');
            if open != close {
                return Err(PyErr::value_error("Invalid IPv6 URL"));
            }
            if open && close {
                check_bracketed_netloc(&n)?;
            }
            netloc = Some(n);
            &body[end..]
        }
        _ => rest,
    };
    let path_is_empty = after
        .chars()
        .take_while(|c| !matches!(c, '?' | '#'))
        .all(is_unsafe);
    if let Some(n) = &netloc {
        check_netloc(n)?;
    }
    Ok(SplitHead {
        scheme,
        netloc,
        path_is_empty,
    })
}

/// `urllib.parse.urlsplit(url, scheme, allow_fragments)`.
pub fn urlsplit(url: &str, scheme: &str, allow_fragments: bool) -> Result<SplitResult, PyErr> {
    let p = urlsplit_parts(url, Some(scheme), allow_fragments)?;
    Ok(SplitResult {
        scheme: p.scheme.unwrap_or_default(),
        netloc: p.netloc.unwrap_or_default(),
        path: p.path,
        query: p.query.unwrap_or_default(),
        fragment: p.fragment.unwrap_or_default(),
    })
}

/// `urllib.parse.urlparse(url, scheme, allow_fragments)`.
pub fn urlparse(url: &str, scheme: &str, allow_fragments: bool) -> Result<ParseResult, PyErr> {
    let p = urlsplit_parts(url, Some(scheme), allow_fragments)?;
    let scheme = p.scheme.unwrap_or_default();
    let (path, params) = if USES_PARAMS.contains(&scheme.as_str()) && p.path.contains(';') {
        let (path, params) = split_params(&p.path);
        (path.to_owned(), params.unwrap_or_default().to_owned())
    } else {
        (p.path, String::new())
    };
    Ok(ParseResult {
        scheme,
        netloc: p.netloc.unwrap_or_default(),
        path,
        params,
        query: p.query.unwrap_or_default(),
        fragment: p.fragment.unwrap_or_default(),
    })
}

fn split_params(url: &str) -> (&str, Option<&str>) {
    let i = if let Some(slash) = url.rfind('/') {
        match url[slash..].find(';') {
            Some(i) => slash + i,
            None => return (url, None),
        }
    } else {
        url.find(';').unwrap_or(0)
    };
    (&url[..i], Some(&url[i + 1..]))
}

/// `urllib.parse.urlunsplit((scheme, netloc, path, query, fragment))`.
pub fn urlunsplit(scheme: &str, netloc: &str, path: &str, query: &str, fragment: &str) -> String {
    let netloc = if netloc.is_empty() {
        (!scheme.is_empty()
            && USES_NETLOC.contains(&scheme)
            && (path.is_empty() || path.starts_with('/')))
        .then_some("")
    } else {
        Some(netloc)
    };
    unsplit(
        (!scheme.is_empty()).then_some(scheme),
        netloc,
        path,
        (!query.is_empty()).then_some(query),
        (!fragment.is_empty()).then_some(fragment),
    )
}

/// `urllib.parse.urlunparse((scheme, netloc, path, params, query, fragment))`.
pub fn urlunparse(
    scheme: &str,
    netloc: &str,
    path: &str,
    params: &str,
    query: &str,
    fragment: &str,
) -> String {
    let netloc = if netloc.is_empty() {
        (!scheme.is_empty()
            && USES_NETLOC.contains(&scheme)
            && (path.is_empty() || path.starts_with('/')))
        .then_some("")
    } else {
        Some(netloc)
    };
    let path = if params.is_empty() {
        Cow::Borrowed(path)
    } else {
        Cow::Owned(format!("{path};{params}"))
    };
    unsplit(
        (!scheme.is_empty()).then_some(scheme),
        netloc,
        &path,
        (!query.is_empty()).then_some(query),
        (!fragment.is_empty()).then_some(fragment),
    )
}

fn unsplit(
    scheme: Option<&str>,
    netloc: Option<&str>,
    url: &str,
    query: Option<&str>,
    fragment: Option<&str>,
) -> String {
    let mut out = String::with_capacity(url.len() + 16);
    if let Some(s) = scheme.filter(|s| !s.is_empty()) {
        out.push_str(s);
        out.push(':');
    }
    if let Some(n) = netloc {
        out.push_str("//");
        out.push_str(n);
        if !url.is_empty() && !url.starts_with('/') {
            out.push('/');
        }
    } else if url.starts_with("//") {
        out.push_str("//");
    }
    out.push_str(url);
    if let Some(q) = query {
        out.push('?');
        out.push_str(q);
    }
    if let Some(f) = fragment {
        out.push('#');
        out.push_str(f);
    }
    out
}

/// `urllib.parse.urljoin(base, url, allow_fragments)`. Python treats a `None` base as an empty one.
pub fn urljoin(base: &str, url: &str, allow_fragments: bool) -> Result<String, PyErr> {
    if base.is_empty() {
        return Ok(url.to_owned());
    }
    if url.is_empty() {
        return Ok(base.to_owned());
    }
    let b = urlsplit_parts(base, None, allow_fragments)?;
    let u = urlsplit_parts(url, None, allow_fragments)?;
    let scheme = u.scheme.or(b.scheme.clone());
    if scheme != b.scheme
        || scheme
            .as_deref()
            .is_some_and(|s| !s.is_empty() && !USES_RELATIVE.contains(&s))
    {
        return Ok(url.to_owned());
    }
    let s = scheme.as_deref();
    let mut netloc = u.netloc;
    if s.is_none_or(|s| s.is_empty() || USES_NETLOC.contains(&s)) {
        if netloc.as_deref().is_some_and(|n| !n.is_empty()) {
            return Ok(unsplit(
                s,
                netloc.as_deref(),
                &u.path,
                u.query.as_deref(),
                u.fragment.as_deref(),
            ));
        }
        netloc = b.netloc.clone();
    }
    let mut query = u.query;
    let mut fragment = u.fragment;
    if u.path.is_empty() {
        if query.is_none() {
            query = b.query;
            if fragment.is_none() {
                fragment = b.fragment;
            }
        }
        return Ok(unsplit(
            s,
            netloc.as_deref(),
            &b.path,
            query.as_deref(),
            fragment.as_deref(),
        ));
    }
    let mut base_parts: Vec<&str> = b.path.split('/').collect();
    if base_parts.last() != Some(&"") {
        base_parts.pop();
    }
    let segments: Vec<&str> = if u.path.starts_with('/') {
        u.path.split('/').collect()
    } else {
        let mut segs = base_parts;
        segs.extend(u.path.split('/'));
        if segs.len() > 2 {
            let last = segs.len() - 1;
            let middle: Vec<&str> = segs[1..last]
                .iter()
                .copied()
                .filter(|s| !s.is_empty())
                .collect();
            let mut out = vec![segs[0]];
            out.extend(middle);
            out.push(segs[last]);
            out
        } else {
            segs
        }
    };
    let mut resolved: Vec<&str> = Vec::new();
    for seg in &segments {
        match *seg {
            ".." => {
                resolved.pop();
            }
            "." => {}
            _ => resolved.push(seg),
        }
    }
    if matches!(segments.last(), Some(&".") | Some(&"..")) {
        resolved.push("");
    }
    let joined = resolved.join("/");
    let path = if joined.is_empty() { "/" } else { &joined };
    Ok(unsplit(
        s,
        netloc.as_deref(),
        path,
        query.as_deref(),
        fragment.as_deref(),
    ))
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// `urllib.parse.unquote_to_bytes(s)`.
pub fn unquote_to_bytes(s: &str) -> Vec<u8> {
    unquote_impl(s.as_bytes())
}

fn unquote_impl(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex_value(b[i + 1]), hex_value(b[i + 2]))
        {
            out.push(h * 16 + l);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// `urllib.parse.unquote(s)`: UTF-8 with errors="replace".
pub fn unquote(s: &str) -> Cow<'_, str> {
    if !s.contains('%') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while !rest.is_empty() {
        let ascii = rest.bytes().take_while(u8::is_ascii).count();
        if ascii > 0 {
            out.push_str(&decode_utf8_replace(&unquote_impl(
                &rest.as_bytes()[..ascii],
            )));
            rest = &rest[ascii..];
        }
        let non_ascii = rest
            .char_indices()
            .find(|(_, c)| c.is_ascii())
            .map_or(rest.len(), |(i, _)| i);
        out.push_str(&rest[..non_ascii]);
        rest = &rest[non_ascii..];
    }
    Cow::Owned(out)
}

/// `urllib.parse.unquote_plus(s)`.
pub fn unquote_plus(s: &str) -> String {
    let s = s.replace('+', " ");
    unquote(&s).into_owned()
}

/// `urllib.parse.quote(s, safe)` for a str: UTF-8, and `safe`'s non-ASCII characters ignored.
pub fn quote(s: &str, safe: &str) -> String {
    let is_safe = |b: u8| {
        b.is_ascii_alphanumeric()
            || b"_.-~".contains(&b)
            || (b.is_ascii() && safe.as_bytes().contains(&b))
    };
    if s.bytes().all(is_safe) {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if is_safe(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(char::from(b"0123456789ABCDEF"[(b >> 4) as usize]));
            out.push(char::from(b"0123456789ABCDEF"[(b & 15) as usize]));
        }
    }
    out
}

/// `urllib.parse.parse_qsl(qs, keep_blank_values, strict_parsing, separator=separator)`.
pub fn parse_qsl(
    qs: &str,
    keep_blank_values: bool,
    strict_parsing: bool,
    separator: &str,
) -> Result<Vec<(String, String)>, PyErr> {
    if separator.is_empty() {
        return Err(PyErr::value_error(
            "Separator must be of type string or bytes.",
        ));
    }
    let mut r = Vec::new();
    if qs.is_empty() {
        return Ok(r);
    }
    for name_value in qs.split(separator) {
        if name_value.is_empty() && !strict_parsing {
            continue;
        }
        let (name, value) = match name_value.split_once('=') {
            Some(nv) => nv,
            None => {
                if strict_parsing {
                    return Err(PyErr::value_error(format!(
                        "bad query field: {}",
                        repr(name_value)
                    )));
                }
                (name_value, "")
            }
        };
        if !value.is_empty() || keep_blank_values {
            r.push((unquote_plus(name), unquote_plus(value)));
        }
    }
    Ok(r)
}

/// `urllib.parse.parse_qs(...)`: each name with its values, in the dict's order.
pub fn parse_qs(
    qs: &str,
    keep_blank_values: bool,
    strict_parsing: bool,
    separator: &str,
) -> Result<Vec<(String, Vec<String>)>, PyErr> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for (name, value) in parse_qsl(qs, keep_blank_values, strict_parsing, separator)? {
        match index.get(&name) {
            Some(&i) => out[i].1.push(value),
            None => {
                index.insert(name.clone(), out.len());
                out.push((name, vec![value]));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn head_agrees_with_urlsplit() {
        let cases = crate::testdata::load("parse", include_str!("../tests/data/parse.json"));
        let mut urls: Vec<String> = Vec::new();
        collect_strings(&cases, &mut urls);
        for extra in [
            "ht\ntp://a.com/x",
            "\n//h/p",
            "http:\t/\n/h",
            "a:\n?x",
            "x:",
            "//[::1",
            "http://[::1]x/",
            "\u{3000}http://a",
            "http://\u{ff1f}x/",
        ] {
            urls.push(extra.to_owned());
        }
        for url in &urls {
            let full = super::urlsplit(url, "", true);
            let head = super::urlsplit_head(url);
            match (full, head) {
                (Ok(f), Ok(h)) => {
                    assert_eq!(f.scheme, h.scheme, "{url:?}");
                    assert_eq!(f.netloc, h.netloc.clone().unwrap_or_default(), "{url:?}");
                    assert_eq!(f.path.is_empty(), h.path_is_empty, "{url:?}");
                }
                (Err(a), Err(b)) => assert_eq!(a, b, "{url:?}"),
                (f, h) => panic!("{url:?}: {f:?} vs {h:?}"),
            }
        }
        assert!(urls.len() > 300);
    }

    fn collect_strings(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::String(s) => out.push(s.clone()),
            serde_json::Value::Array(items) => items.iter().for_each(|v| collect_strings(v, out)),
            serde_json::Value::Object(map) => map.values().for_each(|v| collect_strings(v, out)),
            _ => {}
        }
    }

    use serde_json::{Value, json};

    use super::*;
    use crate::testdata::{Mismatches, outcome, s};

    fn data() -> Value {
        crate::testdata::load("parse", include_str!("../tests/data/parse.json"))
    }

    fn split_parts(r: &SplitResult) -> Value {
        json!([r.scheme, r.netloc, r.path, r.query, r.fragment])
    }

    #[test]
    fn urlsplit_and_urlparse_match_python() {
        let data = data();
        let mut m = Mismatches::new("urlsplit");
        for case in data["split"].as_array().unwrap() {
            let u = s(case, "url");
            let p = urlparse(u, "", true);
            let unparse = match &p {
                Ok(p) => json!(p.geturl()),
                Err(_) => Value::Null,
            };
            let unsplit = match urlsplit(u, "", true) {
                Ok(r) => json!(r.geturl()),
                Err(_) => Value::Null,
            };
            let joins: Vec<Value> = case["join"]
                .as_array()
                .unwrap()
                .iter()
                .map(|j| {
                    let (b, x) = (j[0].as_str().unwrap(), j[1].as_str().unwrap());
                    json!([b, x, outcome(urljoin(b, x, true), |v| json!(v))])
                })
                .collect();
            let got = json!({
                "url": u,
                "split": outcome(urlsplit(u, "", true), |r| json!({
                    "parts": split_parts(&r), "hostname": r.hostname(), "username": r.username(),
                    "password": r.password(), "port": outcome(r.port(), |p| json!(p)), "geturl": r.geturl(),
                })),
                "split_nofrag": outcome(urlsplit(u, "", false), |r| split_parts(&r)),
                "split_scheme": outcome(urlsplit(u, " ht\ttp\n", true), |r| split_parts(&r)),
                "parse": outcome(p, |r| json!([r.scheme, r.netloc, r.path, r.params, r.query, r.fragment])),
                "unparse": unparse,
                "unsplit": unsplit,
                "join": joins,
            });
            m.check(u, &got, case);
        }
        m.finish();
    }

    #[test]
    fn urljoin_matches_python() {
        let data = data();
        let mut m = Mismatches::new("urljoin");
        for case in data["join"].as_array().unwrap() {
            let (b, u) = (s(case, "base"), s(case, "url"));
            let got = json!({
                "base": b, "url": u,
                "out": outcome(urljoin(b, u, true), |v| json!(v)),
                "nofrag": outcome(urljoin(b, u, false), |v| json!(v)),
            });
            m.check((b, u), &got, case);
        }
        m.finish();
    }

    #[test]
    fn quote_and_unquote_match_python() {
        let data = data();
        let mut m = Mismatches::new("quote");
        for case in data["quote"].as_array().unwrap() {
            let q = s(case, "s");
            let hex: String = unquote_to_bytes(q)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let got = json!({
                "s": q, "unquote": unquote(q), "unquote_plus": unquote_plus(q), "quote": quote(q, "/"),
                "quote_safe": quote(q, "/:@&=+$,;~\u{e9}%"), "quote_empty": quote(q, ""),
                "unquote_bytes": hex,
            });
            m.check(q, &got, case);
        }
        m.finish();
    }

    #[test]
    fn parse_qs_matches_python() {
        let data = data();
        let mut m = Mismatches::new("parse_qs");
        for case in data["qs"].as_array().unwrap() {
            let q = s(case, "qs");
            let mut got = serde_json::Map::new();
            got.insert("qs".into(), json!(q));
            for keep in [false, true] {
                for strict in [false, true] {
                    for sep in ["&", ";"] {
                        let key = format!("{}{}{sep}", keep as u8, strict as u8);
                        got.insert(
                            format!("qsl{key}"),
                            outcome(parse_qsl(q, keep, strict, sep), |v| json!(v)),
                        );
                        got.insert(
                            format!("qs{key}"),
                            outcome(parse_qs(q, keep, strict, sep), |v| json!(v)),
                        );
                    }
                }
            }
            m.check(q, &Value::Object(got), case);
        }
        m.finish();
    }
}
