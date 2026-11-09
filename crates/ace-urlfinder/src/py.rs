//! The Python this port calls, from `ace-pycompat`, under the names urlfinderlib uses.

pub use ace_pycompat::PyErr;
pub use ace_pycompat::parse::{SplitResult, unquote};
pub use ace_pycompat::pystr::{
    decode_utf8_ignore, is_space, lower, rstrip_chars, splitlines, strip,
};

pub type PyResult<T> = Result<T, PyErr>;

/// `urlsplit(url)`.
pub fn urlsplit(url: &str) -> PyResult<SplitResult> {
    ace_pycompat::parse::urlsplit(url, "", true)
}

/// `urlparse(url)`.
pub fn urlparse(url: &str) -> PyResult<ace_pycompat::parse::ParseResult> {
    ace_pycompat::parse::urlparse(url, "", true)
}

/// `urljoin(base, url)`.
pub fn urljoin(base: &str, url: &str) -> PyResult<String> {
    ace_pycompat::parse::urljoin(base, url, true)
}

/// `quote(s, safe)`.
pub fn quote(s: &str, safe: &str) -> String {
    ace_pycompat::parse::quote(s, safe)
}

/// `parse_qs(qs)` with its defaults, as an ordered dict.
pub fn parse_qs(qs: &str) -> PyResult<Vec<(String, Vec<String>)>> {
    ace_pycompat::parse::parse_qs(qs, false, false, "&")
}

/// `html.unescape`.
pub fn html_unescape(s: &str) -> String {
    ace_pycompat::html::unescape(s).into_owned()
}

/// `html.escape(s)`.
pub fn html_escape(s: &str) -> String {
    ace_pycompat::html::escape(s, true).into_owned()
}

/// `base64.b64decode(s)`.
pub fn b64decode(s: &str) -> PyResult<Vec<u8>> {
    ace_pycompat::base64::b64decode(s)
}

/// `base64.urlsafe_b64decode(s)`.
pub fn urlsafe_b64decode(s: &str) -> PyResult<Vec<u8>> {
    ace_pycompat::base64::urlsafe_b64decode(s)
}

/// `bytes.decode("ascii")`.
pub fn decode_ascii(b: Vec<u8>) -> PyResult<String> {
    if b.is_ascii() {
        Ok(String::from_utf8(b).unwrap_or_default())
    } else {
        Err(PyErr::new(
            "builtins",
            "UnicodeDecodeError",
            "'ascii' codec can't decode",
        ))
    }
}

/// `bytes.decode("utf-8")`.
pub fn decode_utf8(b: Vec<u8>) -> PyResult<String> {
    String::from_utf8(b).map_err(|_| {
        PyErr::new(
            "builtins",
            "UnicodeDecodeError",
            "'utf-8' codec can't decode",
        )
    })
}

/// `ipaddress.ip_address(s)` doesn't raise.
pub fn is_ip_address(s: &str) -> bool {
    ace_pycompat::ipaddress::ip_address(s).is_ok()
}

/// `idna.encode(s)`, the package's.
pub fn idna_encode(s: &str) -> PyResult<Vec<u8>> {
    ace_pycompat::idna::encode(s).map(String::into_bytes)
}

/// `idna.decode(s)`.
pub fn idna_decode(s: &str) -> PyResult<String> {
    ace_pycompat::idna::decode(s)
}

/// `except idna.core.IDNAError`.
pub fn is_idna_error(e: &PyErr) -> bool {
    e.is_instance("idna.core", "IDNAError")
}

/// `except UnicodeError`.
pub fn is_unicode_error(e: &PyErr) -> bool {
    e.is_instance("builtins", "UnicodeError")
}

/// `s.encode("idna")`, the codec's.
pub fn codec_idna_encode(s: &str) -> PyResult<Vec<u8>> {
    ace_pycompat::codecs_idna::encode(s).map(String::into_bytes)
}

/// `b.decode("idna")`.
pub fn codec_idna_decode(b: &[u8]) -> PyResult<String> {
    ace_pycompat::codecs_idna::decode(b)
}

/// `unicodedata.category(c)`.
pub fn category(c: char) -> &'static str {
    ace_pycompat::unicodedata::category(c)
}

/// `normalize("NFKC", c) != c` and all ASCII.
pub fn nfkc_maps_to_other_ascii(c: char) -> bool {
    ace_pycompat::unicodedata::nfkc_maps_to_other_ascii(c)
}

/// `validators.url(value, simple_host=simple_host)`.
pub fn validators_url(value: &str, simple_host: bool) -> bool {
    ace_pycompat::validators::url(value, simple_host)
}

/// `validators.email(value)`.
pub fn validators_email(value: &str) -> bool {
    ace_pycompat::validators::email(value)
}

/// `validators.domain(value)`.
pub fn validators_domain(value: &str) -> bool {
    ace_pycompat::validators::domain(value)
}

/// `re.search(r"\s", s)`.
pub fn has_space(s: &str) -> bool {
    s.chars().any(is_space)
}

/// Python IGNORECASE: the ASCII letter that `c` matches in `[a-z]`, as `re` does: ASCII letters,
/// İ and ı as i, ſ as s and the Kelvin sign as k.
pub fn ignorecase_letter(c: char) -> Option<char> {
    match c {
        'a'..='z' => Some(c),
        'A'..='Z' => Some(c.to_ascii_lowercase()),
        '\u{130}' | '\u{131}' => Some('i'),
        '\u{17f}' => Some('s'),
        '\u{212a}' => Some('k'),
        _ => None,
    }
}
