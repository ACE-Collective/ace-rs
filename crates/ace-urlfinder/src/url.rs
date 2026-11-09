//! `urlfinderlib/url.py`: `URL`, with its spellings, its validity and its child URLs, and
//! `URLList`.
//!
//! Python computes each property once and caches it; so does this. A property that can raise
//! in Python returns a `PyResult`, and the exception travels as it would there: `find_urls`
//! then raises, and ace3's `url_extraction` logs it and adds nothing.

use std::cell::OnceCell;
use std::collections::{BTreeSet, HashSet};

use crate::helpers::{self, build_url};
use crate::py::{self, PyResult, SplitResult};

/// `parse_qs`'s dict, in its order.
type QueryDict = Vec<(String, Vec<String>)>;

/// One URL candidate.
pub struct Url {
    value: String,
    split: OnceCell<SplitResult>,
    /// The scheme and netloc alone, which most URLs that aren't URLs fail on.
    head: OnceCell<(String, String)>,
    parsed: OnceCell<PyResult<(String, String)>>,
    netloc_idna: OnceCell<PyResult<String>>,
    netloc_unicode: OnceCell<PyResult<String>>,
    path_original: OnceCell<String>,
    path_all_decoded: OnceCell<String>,
    identity: OnceCell<PyResult<String>>,
    is_url: OnceCell<PyResult<bool>>,
    permutations: OnceCell<PyResult<BTreeSet<String>>>,
    query_dict: OnceCell<PyResult<QueryDict>>,
}

impl Url {
    /// `URL(value)`: the value without trailing `/`, then without trailing `\`.
    pub fn new(value: &str) -> Url {
        let value = value.trim_end_matches('/').trim_end_matches('\\');
        Url {
            value: value.to_owned(),
            split: OnceCell::new(),
            head: OnceCell::new(),
            parsed: OnceCell::new(),
            netloc_idna: OnceCell::new(),
            netloc_unicode: OnceCell::new(),
            path_original: OnceCell::new(),
            path_all_decoded: OnceCell::new(),
            identity: OnceCell::new(),
            is_url: OnceCell::new(),
            permutations: OnceCell::new(),
            query_dict: OnceCell::new(),
        }
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    /// `split_value`: `urlsplit(value)`, or `urlsplit("")` where that raises.
    pub fn split_value(&self) -> &SplitResult {
        self.split.get_or_init(|| {
            py::urlsplit(&self.value)
                .or_else(|_| py::urlsplit(""))
                .unwrap_or_default()
        })
    }

    /// `split_value`'s scheme and netloc, from `urlsplit_head`, which raises where `urlsplit` does.
    fn head(&self) -> &(String, String) {
        self.head
            .get_or_init(|| match ace_pycompat::parse::urlsplit_head(&self.value) {
                Ok(head) => (head.scheme, head.netloc.unwrap_or_default()),
                Err(_) => (String::new(), String::new()),
            })
    }

    fn netloc(&self) -> &str {
        &self.head().1
    }

    fn hostname(&self) -> Option<String> {
        SplitResult {
            netloc: self.netloc().to_owned(),
            ..SplitResult::default()
        }
        .hostname()
    }

    /// `parse_value`'s query and fragment: `urlparse(value)`, which isn't guarded.
    fn parsed(&self) -> PyResult<&(String, String)> {
        self.parsed
            .get_or_init(|| py::urlparse(&self.value).map(|p| (p.query, p.fragment)))
            .as_ref()
            .map_err(Clone::clone)
    }

    /// `query_dict`: `parse_qs(parse_value.query)`.
    pub fn query_dict(&self) -> PyResult<&[(String, Vec<String>)]> {
        self.query_dict
            .get_or_init(|| self.parsed().and_then(|(query, _)| py::parse_qs(query)))
            .as_ref()
            .map(Vec::as_slice)
            .map_err(Clone::clone)
    }

    /// `fragment_dict`.
    fn fragment_dict(&self) -> PyResult<Vec<(String, Vec<String>)>> {
        let (_, fragment) = self.parsed()?;
        py::parse_qs(fragment)
    }

    fn query_has(&self, key: &str) -> PyResult<bool> {
        Ok(self.query_dict()?.iter().any(|(k, _)| k == key))
    }

    fn query_first(&self, key: &str) -> PyResult<Option<String>> {
        Ok(self
            .query_dict()?
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, values)| values.first().cloned()))
    }

    /// `identity`: what every spelling of the URL shares.
    pub fn identity(&self) -> PyResult<&str> {
        self.identity
            .get_or_init(|| {
                let idna = self.netloc_idna()?;
                let netloc = if idna.is_empty() {
                    self.netloc_original()
                } else {
                    idna.to_owned()
                };
                Ok(format!(
                    "{}://{netloc}{}",
                    py::lower(&self.split_value().scheme),
                    self.path_all_decoded()
                ))
            })
            .as_deref()
            .map_err(Clone::clone)
    }

    /// `is_mandrillapp`, None where Python's is None (no host).
    fn is_mandrillapp(&self) -> PyResult<bool> {
        match self.hostname() {
            Some(host) if !host.is_empty() => {
                Ok(host.contains("mandrillapp.com") && self.query_has("p")?)
            }
            _ => Ok(false),
        }
    }

    fn value_lower(&self) -> String {
        py::lower(&self.value).into_owned()
    }

    fn is_proofpoint_v2(&self) -> PyResult<bool> {
        match self.hostname() {
            Some(host) if !host.is_empty() => {
                let lower = self.value_lower();
                Ok(host.contains("urldefense")
                    && (lower.contains("urldefense.proofpoint.com/v2")
                        || lower.contains("urldefense.com/v2"))
                    && self.query_has("u")?)
            }
            _ => Ok(false),
        }
    }

    fn is_proofpoint_v3(&self) -> bool {
        match self.hostname() {
            Some(host) if !host.is_empty() => {
                let lower = self.value_lower();
                host.contains("urldefense")
                    && (lower.contains("urldefense.proofpoint.com/v3")
                        || lower.contains("urldefense.com/v3"))
            }
            _ => false,
        }
    }

    fn is_netloc_ipv4(&self) -> bool {
        match self.hostname() {
            Some(host) if !host.is_empty() => py::is_ip_address(&host),
            _ => false,
        }
    }

    fn is_netloc_localhost(&self) -> bool {
        match self.hostname() {
            Some(host) if !host.is_empty() => {
                let host = py::lower(&host);
                host == "localhost" || host == "localhost.localdomain"
            }
            _ => false,
        }
    }

    fn is_netloc_valid_tld(&self) -> bool {
        match self.hostname() {
            // tld.get_tld(self.value) splits the value again, as split_value did
            Some(host) if !host.is_empty() && host.contains('.') => {
                let host_only = SplitResult {
                    netloc: self.netloc().to_owned(),
                    ..SplitResult::default()
                };
                ace_pycompat::tld::get_tld_of_split(&host_only).is_some_and(|t| !t.is_empty())
            }
            _ => false,
        }
    }

    /// `is_url`.
    pub fn is_url(&self) -> PyResult<bool> {
        self.is_url
            .get_or_init(|| {
                let v = &self.value;
                if !v.contains('.') || !v.contains(':') || !v.contains('/') {
                    return Ok(false);
                }
                if !(self.is_netloc_valid_tld()
                    || self.is_netloc_ipv4()
                    || self.is_netloc_localhost())
                {
                    return Ok(false);
                }
                self.is_valid_format()
            })
            .clone()
    }

    /// `is_url_ascii`.
    pub fn is_url_ascii(&self) -> PyResult<bool> {
        // an ASCII value is its own ASCII spelling
        if self.value.is_ascii() {
            return self.is_url();
        }
        Url::new(&helpers::get_ascii_url(&self.value)).is_url()
    }

    /// `is_valid_format`.
    fn is_valid_format(&self) -> PyResult<bool> {
        let netloc = self.netloc_idna()?;
        if !netloc_format(netloc) {
            return Ok(false);
        }
        let encoded = build_url(&self.head().0, netloc, &self.path_percent_encoded());
        Ok(py::validators_url(&encoded, true))
    }

    /// `netloc_idna`.
    pub fn netloc_idna(&self) -> PyResult<&str> {
        self.netloc_idna
            .get_or_init(|| self.compute_netloc_idna())
            .as_deref()
            .map_err(Clone::clone)
    }

    fn compute_netloc_idna(&self) -> PyResult<String> {
        let mut netloc = self.netloc().to_owned();
        if netloc.contains('%') {
            netloc = py::unquote(&netloc).into_owned();
        }
        if netloc.is_ascii() {
            return Ok(py::lower(&netloc).into_owned());
        }
        let hostname = py::urlsplit(&format!("http://{netloc}"))?
            .hostname()
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| netloc.clone());
        match py::idna_encode(&hostname) {
            Ok(encoded) => {
                let idna_hostname = py::lower(&py::decode_utf8(encoded)?).into_owned();
                Ok(py::lower(&netloc).replace(py::lower(&hostname).as_ref(), &idna_hostname))
            }
            Err(e) if py::is_idna_error(&e) => {
                let hostname = py::urlsplit(&format!("http://{netloc}"))?
                    .hostname()
                    .filter(|h| !h.is_empty())
                    .unwrap_or_else(|| netloc.clone());
                for c in hostname.chars() {
                    if c.is_ascii() {
                        continue;
                    }
                    if matches!(py::category(c), "Pi" | "Pf") || py::nfkc_maps_to_other_ascii(c) {
                        return Ok(String::new());
                    }
                }
                match py::codec_idna_encode(&hostname) {
                    Ok(encoded) => {
                        let idna_hostname =
                            py::lower(&py::decode_utf8_ignore(&encoded)).into_owned();
                        Ok(py::lower(&netloc)
                            .replace(py::lower(&hostname).as_ref(), &idna_hostname))
                    }
                    Err(e) if py::is_unicode_error(&e) => Ok(String::new()),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// `netloc_original`.
    pub fn netloc_original(&self) -> String {
        py::lower(self.netloc()).into_owned()
    }

    /// `netloc_unicode`.
    pub fn netloc_unicode(&self) -> PyResult<&str> {
        self.netloc_unicode
            .get_or_init(|| {
                let mut netloc = self.netloc().to_owned();
                if netloc.contains('%') {
                    netloc = py::unquote(&netloc).into_owned();
                }
                if !netloc.is_ascii() {
                    return Ok(py::lower(&netloc).into_owned());
                }
                match py::idna_decode(&netloc) {
                    Ok(decoded) => Ok(py::lower(&decoded).into_owned()),
                    Err(e) if py::is_idna_error(&e) => {
                        Ok(py::lower(&py::codec_idna_decode(netloc.as_bytes())?).into_owned())
                    }
                    Err(e) => Err(e),
                }
            })
            .as_deref()
            .map_err(Clone::clone)
    }

    /// `path_original`: path, query and fragment.
    pub fn path_original(&self) -> &str {
        self.path_original.get_or_init(|| {
            let split = self.split_value();
            let mut path = split.path.clone();
            if (!split.path.is_empty() || !split.query.is_empty() || !split.fragment.is_empty())
                && !path.starts_with('/')
            {
                path.insert(0, '/');
            }
            if !split.query.is_empty() {
                path.push('?');
                path.push_str(&split.query);
            }
            if !split.fragment.is_empty() {
                path.push('#');
                path.push_str(&split.fragment);
            }
            path
        })
    }

    /// `path_all_decoded`.
    pub fn path_all_decoded(&self) -> &str {
        self.path_all_decoded
            .get_or_init(|| py::html_unescape(&py::unquote(self.path_original())))
    }

    fn path_html_decoded(&self) -> String {
        py::html_unescape(self.path_original())
    }

    fn path_html_encoded(&self) -> String {
        py::html_escape(self.path_all_decoded())
    }

    fn path_percent_decoded(&self) -> String {
        py::unquote(self.path_original()).into_owned()
    }

    /// `path_percent_encoded`, with line breaks left as they are.
    fn path_percent_encoded(&self) -> String {
        py::quote(self.path_all_decoded(), "/\n\r")
    }

    /// `permutations`: every netloc spelling with every path spelling.
    pub fn permutations(&self) -> PyResult<&BTreeSet<String>> {
        self.permutations
            .get_or_init(|| {
                let netlocs = [
                    self.netloc_idna()?.to_owned(),
                    self.netloc_original(),
                    self.netloc_unicode()?.to_owned(),
                ];
                let paths = [
                    self.path_all_decoded().to_owned(),
                    self.path_original().to_owned(),
                    self.path_html_decoded(),
                    self.path_html_encoded(),
                    self.path_percent_decoded(),
                    self.path_percent_encoded(),
                ];
                let scheme = &self.split_value().scheme;
                Ok(netlocs
                    .iter()
                    .flat_map(|netloc| {
                        paths
                            .iter()
                            .map(move |path| build_url(scheme, netloc, path))
                    })
                    .collect())
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    fn get_query_values(&self) -> PyResult<BTreeSet<String>> {
        let mut values = BTreeSet::new();
        for url in self.permutations()? {
            for (_, list) in Url::new(url).query_dict()? {
                values.extend(list.iter().cloned());
            }
        }
        Ok(values)
    }

    fn get_fragment_values(&self) -> PyResult<BTreeSet<String>> {
        let mut values = BTreeSet::new();
        for url in self.permutations()? {
            for (_, list) in Url::new(url).fragment_dict()? {
                values.extend(list);
            }
        }
        Ok(values)
    }

    fn valid(values: BTreeSet<String>) -> PyResult<Vec<String>> {
        let mut urls = Vec::new();
        for value in values {
            if Url::new(&value).is_url()? {
                urls.push(value);
            }
        }
        Ok(urls)
    }

    /// `get_base64_values`: base64 URLs after a quote, `#` or `/` in the path.
    fn get_base64_values(&self) -> BTreeSet<String> {
        let mut values = BTreeSet::new();
        for token in base64_url_tokens(self.path_original()) {
            if helpers::is_base64_ascii(token)
                && let Ok(decoded) =
                    py::b64decode(&format!("{token}===")).and_then(py::decode_ascii)
            {
                values.insert(decoded);
            }
        }
        values
    }

    fn get_base64_urls(&self) -> PyResult<Vec<String>> {
        let fixed: BTreeSet<String> = self
            .get_base64_values()
            .iter()
            .map(|v| helpers::fix_possible_value(v))
            .collect();
        Url::valid(fixed)
    }

    fn get_base64_param_urls(&self, domain_as_url: bool) -> PyResult<BTreeSet<String>> {
        let mut urls = BTreeSet::new();
        let split = self.split_value();
        if split.query.is_empty() {
            return Ok(urls);
        }
        for (_, values) in self.query_dict()? {
            for value in values {
                for (token, decoded) in iter_base64_ioc_tokens(value, domain_as_url) {
                    let new_query = split.query.replacen(token, &decoded, 1);
                    let mut url = format!(
                        "{}://{}{}?{new_query}",
                        split.scheme, split.netloc, split.path
                    );
                    if !split.fragment.is_empty() {
                        url.push('#');
                        url.push_str(&split.fragment);
                    }
                    urls.insert(url);
                }
            }
        }
        Ok(urls)
    }

    fn get_base64_path_urls(&self, domain_as_url: bool) -> BTreeSet<String> {
        let mut urls = BTreeSet::new();
        let split = self.split_value();
        if split.path.is_empty() {
            return urls;
        }
        for segment in split.path.split('/') {
            for (token, decoded) in iter_base64_ioc_tokens(segment, domain_as_url) {
                let mut url = format!(
                    "{}://{}{}",
                    split.scheme,
                    split.netloc,
                    split.path.replacen(token, &decoded, 1)
                );
                if !split.query.is_empty() {
                    url.push('?');
                    url.push_str(&split.query);
                }
                if !split.fragment.is_empty() {
                    url.push('#');
                    url.push_str(&split.fragment);
                }
                urls.insert(url);
            }
        }
        urls
    }

    /// `get_child_urls`.
    pub fn get_child_urls(&self, domain_as_url: bool) -> PyResult<Vec<Url>> {
        let mut children: Vec<String> = Vec::new();
        children.extend(Url::valid(self.get_query_values()?)?);
        children.extend(Url::valid(self.get_fragment_values()?)?);
        children.extend(self.get_base64_urls()?);
        children.extend(self.get_base64_param_urls(domain_as_url)?);
        children.extend(self.get_base64_path_urls(domain_as_url));
        if self.is_mandrillapp()? {
            let decoded = self.decode_mandrillapp()?;
            if !decoded.is_empty() {
                children.push(decoded);
            }
        }
        if self.is_proofpoint_v2()? {
            children.push(self.decode_proofpoint_v2()?);
        }
        if self.is_proofpoint_v3() {
            children.push(self.decode_proofpoint_v3()?);
        }
        Ok(children
            .iter()
            .filter(|u| !u.is_empty() && **u != self.value)
            .map(|u| Url::new(u))
            .collect())
    }

    /// `decode_mandrillapp`.
    fn decode_mandrillapp(&self) -> PyResult<String> {
        let Some(p) = self.query_first("p")? else {
            return Ok(String::new());
        };
        let base64_string = p.replace('_', "/");
        let bytes = match py::b64decode(&format!("{base64_string}===")) {
            Ok(bytes) => bytes,
            Err(e) if e.is_instance("binascii", "Error") => return Ok(String::new()),
            Err(e) => return Err(e),
        };
        let Some(outer) = crate::pyjson::loads_bytes(&bytes)? else {
            return Ok(String::new());
        };
        let Some(inner_text) = outer.get("p") else {
            return Ok(String::new());
        };
        let Some(inner) = crate::pyjson::loads_value_str(inner_text)? else {
            return Ok(String::new());
        };
        let Some(url) = inner.get("url").and_then(|v| v.as_str()) else {
            return Ok(String::new());
        };
        let url = url.to_owned();
        let possible = helpers::fix_possible_url(&url, false);
        Ok(if Url::new(&possible).is_url()? {
            possible
        } else {
            String::new()
        })
    }

    /// `decode_proofpoint_v2`.
    fn decode_proofpoint_v2(&self) -> PyResult<String> {
        let Some(query_url) = self.query_first("u")? else {
            return Ok(String::new());
        };
        let translated: String = query_url
            .chars()
            .map(|c| match c {
                '-' => '%',
                '_' => '/',
                c => c,
            })
            .collect();
        let url = py::html_unescape(&py::unquote(&translated));
        let possible = helpers::fix_possible_url(&url, false);
        Ok(if Url::new(&possible).is_url()? {
            possible
        } else {
            String::new()
        })
    }

    /// `decode_proofpoint_v3`, Proofpoint's own decoder.
    fn decode_proofpoint_v3(&self) -> PyResult<String> {
        let Some((embedded, base64_characters)) = proofpoint_v3_match(&self.value) else {
            return Ok(String::new());
        };
        let mut embedded_url = embedded.to_owned();
        if let Some((scheme, rest)) = v3_single_slash(&embedded_url) {
            embedded_url = format!("{scheme}/{rest}");
        }
        let embedded_url = py::unquote(&embedded_url).into_owned();
        let bytes = match py::urlsafe_b64decode(&format!("{base64_characters}==")) {
            Ok(bytes) => bytes,
            Err(e) if e.is_instance("binascii", "Error") => return Ok(String::new()),
            Err(e) => return Err(e),
        };
        let Ok(decoded) = String::from_utf8(bytes) else {
            return Ok(String::new());
        };
        let decoded: Vec<char> = decoded.chars().collect();
        let Some(substituted) = v3_substitute(&embedded_url, &decoded) else {
            return Ok(String::new());
        };
        let fixed = helpers::fix_possible_url(&substituted, false);
        Ok(if Url::new(&fixed).is_url()? {
            fixed
        } else {
            String::new()
        })
    }
}

/// `re.match(r"^[a-zA-Z0-9\-\.\:\@]{1,255}$", netloc)`, where `$` also matches before a final
/// newline.
fn netloc_format(netloc: &str) -> bool {
    let body = netloc.strip_suffix('\n').unwrap_or(netloc);
    (1..=255).contains(&body.len())
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b':' | b'@'))
}

/// `base64_pattern.findall(path)`: `[\"\'\#\/](((aHR0c)|(ZnRw))[a-zA-Z0-9]+)`'s first group.
fn base64_url_tokens(path: &str) -> Vec<&str> {
    let bytes = path.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if matches!(bytes[i], b'"' | b'\'' | b'#' | b'/') {
            let start = i + 1;
            let prefix = if path[start..].starts_with("aHR0c") {
                5
            } else if path[start..].starts_with("ZnRw") {
                4
            } else {
                0
            };
            if prefix > 0 {
                let mut end = start + prefix;
                while end < bytes.len() && bytes[end].is_ascii_alphanumeric() {
                    end += 1;
                }
                if end > start + prefix {
                    tokens.push(&path[start..end]);
                    i = end;
                    continue;
                }
            }
        }
        i += 1;
    }
    tokens
}

/// `base64_token_pattern.finditer(text)`: `[A-Za-z0-9+/\-_]+=*`.
fn base64_runs(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let class = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_');
    let mut runs = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if class(bytes[i]) {
            let start = i;
            while i < bytes.len() && class(bytes[i]) {
                i += 1;
            }
            while i < bytes.len() && bytes[i] == b'=' {
                i += 1;
            }
            runs.push(&text[start..i]);
        } else {
            i += 1;
        }
    }
    runs
}

/// `email_in_text_pattern.search`: `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`.
fn has_email(text: &str) -> bool {
    static PATTERN: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").expect("a regex")
    });
    PATTERN.is_match(text)
}

/// `url_in_text_pattern.search`: `(?i)\b(?:https?|ftp)://`, with Python's `\b` and IGNORECASE.
fn has_url_scheme(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let lowered: Vec<Option<char>> = chars.iter().map(|c| py::ignorecase_letter(*c)).collect();
    let word = |c: char| ace_pycompat::pystr::is_word(c);
    for start in 0..chars.len() {
        // \b before a word character: the previous one isn't one
        if start > 0 && word(chars[start - 1]) {
            continue;
        }
        if !word(chars[start]) {
            continue;
        }
        let letters = |n: usize, word: &str| {
            word.chars()
                .enumerate()
                .all(|(k, w)| lowered.get(start + k).copied().flatten() == Some(w))
                && start + n <= chars.len()
        };
        let after = |n: usize| chars.get(start + n..start + n + 3) == Some(&[':', '/', '/'][..]);
        if (letters(5, "https") && after(5))
            || (letters(4, "http") && after(4))
            || (letters(3, "ftp") && after(3))
        {
            return true;
        }
    }
    false
}

/// `decode_base64_ioc`.
pub fn decode_base64_ioc(value: &str, domain_as_url: bool) -> String {
    if value.chars().count() < 8 {
        return String::new();
    }
    let decoded = helpers::decode_base64_ascii(value);
    if decoded.is_empty() || decoded == value {
        return String::new();
    }
    if has_email(&decoded) || has_url_scheme(&decoded) {
        return decoded;
    }
    if domain_as_url && py::validators_domain(&decoded) {
        return decoded;
    }
    String::new()
}

/// `iter_base64_ioc_tokens`.
pub fn iter_base64_ioc_tokens(text: &str, domain_as_url: bool) -> Vec<(&str, String)> {
    base64_runs(text)
        .into_iter()
        .filter_map(|token| {
            let decoded = decode_base64_ioc(token, domain_as_url);
            (!decoded.is_empty()).then_some((token, decoded))
        })
        .collect()
}

/// `re.search(r"v3/__(.+?)__;(.*?)!", value, re.IGNORECASE)`'s two groups. `.` is anything but a
/// newline, and the only letter, `v`, has no other case-insensitive match.
fn proofpoint_v3_match(value: &str) -> Option<(&str, &str)> {
    let mut from = 0;
    while let Some(at) = find_v3(value, from) {
        let group1_start = at + 5;
        if let Some(found) = v3_groups(value, group1_start) {
            return Some(found);
        }
        from = at + 1;
    }
    None
}

fn find_v3(value: &str, from: usize) -> Option<usize> {
    let bytes = value.as_bytes();
    (from..bytes.len())
        .find(|&i| matches!(bytes[i], b'v' | b'V') && bytes[i + 1..].starts_with(b"3/__"))
}

/// `(.+?)__;(.*?)!` from `start`: the shortest first group (at least one character) with `__;`
/// after it and a `!` later on the same line.
fn v3_groups(value: &str, start: usize) -> Option<(&str, &str)> {
    let rest = &value[start..];
    let line_end = rest.find('\n').unwrap_or(rest.len());
    let line = &rest[..line_end];
    let first = line.chars().next()?;
    let search = first.len_utf8();
    let end1 = search + line[search..].find("__;")?;
    let after = &line[end1 + 3..];
    // with no `!` after the first `__;` on the line, none comes after a later one either
    let bang = after.find('!')?;
    Some((&line[..end1], &after[..bang]))
}

/// `v3_single_slash.findall(url)`: `^([a-z0-9+.-]+:/)([^/].+)` with IGNORECASE.
fn v3_single_slash(url: &str) -> Option<(&str, &str)> {
    let mut end = 0;
    for (i, c) in url.char_indices() {
        if py::ignorecase_letter(c).is_some() || c.is_ascii_digit() || matches!(c, '+' | '.' | '-')
        {
            end = i + c.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 || !url[end..].starts_with(":/") {
        return None;
    }
    let scheme = &url[..end + 2];
    let rest = &url[end + 2..];
    let mut chars = rest.chars();
    let first = chars.next()?;
    if first == '/' {
        return None;
    }
    // .+ : one or more characters up to a newline
    let tail = &rest[first.len_utf8()..];
    let tail_len = tail.find('\n').unwrap_or(tail.len());
    if tail_len == 0 {
        return None;
    }
    Some((scheme, &rest[..first.len_utf8() + tail_len]))
}

/// `re.sub(r"\*(\*.)?", replace_token, text)`, or None where `replace_token` raises.
fn v3_substitute(text: &str, decoded: &[char]) -> Option<String> {
    let run_values = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(text.len());
    let mut marker = 0usize;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '*' {
            out.push(c);
            continue;
        }
        let mut lookahead = chars.clone();
        let run = match (lookahead.next(), lookahead.next()) {
            (Some('*'), Some(x)) if x != '\n' => Some(x),
            _ => None,
        };
        match run {
            Some(x) => {
                chars.next();
                chars.next();
                let length = run_values.find(x)? + 2;
                let end = (marker + length).min(decoded.len());
                out.extend(&decoded[marker.min(end)..end]);
                marker += length;
            }
            None => {
                out.push(*decoded.get(marker)?);
                marker += 1;
            }
        }
    }
    Some(out)
}

/// `_spelling_preference`: the spelling without HTML entities first, then the one with more
/// percent-encoding, then by value.
fn spelling_preference(url: &Url) -> (bool, i64, &str) {
    let value = url.value();
    (
        py::html_unescape(value) != value,
        -(value.matches('%').count() as i64),
        value,
    )
}

/// `URLList`: URLs, one per spelling.
#[derive(Default)]
pub struct UrlList {
    pub data: Vec<Url>,
}

impl UrlList {
    pub fn new() -> UrlList {
        UrlList::default()
    }

    /// `URLList([URL(u) for u in values])`: the list constructor, which checks nothing.
    pub fn from_values<'v>(values: impl IntoIterator<Item = &'v str>) -> UrlList {
        UrlList {
            data: values.into_iter().map(Url::new).collect(),
        }
    }

    /// `append`: a URL, or its ASCII spelling if only that is one.
    pub fn append(&mut self, value: &str) -> PyResult<()> {
        let url = Url::new(value);
        if url.is_url()? {
            self.data.push(url);
        } else if url.is_url_ascii()? {
            self.data
                .push(Url::new(&helpers::get_ascii_url(url.value())));
        }
        Ok(())
    }

    /// `+= values`.
    pub fn extend<'v>(&mut self, values: impl IntoIterator<Item = &'v String>) -> PyResult<()> {
        for value in values {
            self.append(value)?;
        }
        Ok(())
    }

    /// `get_all_urls`: each URL and, transitively, its child URLs.
    pub fn get_all_urls(self, domain_as_url: bool) -> PyResult<BTreeSet<String>> {
        let mut all = HashSet::new();
        let mut stack = self.data;
        while let Some(url) = stack.pop() {
            if all.contains(url.value()) {
                continue;
            }
            all.insert(url.value().to_owned());
            for child in url.get_child_urls(domain_as_url)? {
                if !all.contains(child.value()) {
                    stack.push(child);
                }
            }
        }
        Ok(all.into_iter().collect())
    }

    /// `distinct_values`: one spelling of each URL, the preferred one.
    pub fn distinct_values(&self) -> PyResult<BTreeSet<String>> {
        let mut order: Vec<&Url> = self.data.iter().collect();
        order.sort_by(|a, b| spelling_preference(a).cmp(&spelling_preference(b)));
        let mut identities = HashSet::new();
        let mut values = BTreeSet::new();
        for url in order {
            if identities.insert(url.identity()?.to_owned()) {
                values.insert(url.value().to_owned());
            }
        }
        Ok(values)
    }
}

/// For the URL class's users: the child URLs of one URL, as `URL(value).child_urls` gives them.
pub fn child_urls(value: &str) -> PyResult<Vec<String>> {
    Ok(Url::new(value)
        .get_child_urls(false)?
        .into_iter()
        .map(|url| url.value)
        .collect())
}
