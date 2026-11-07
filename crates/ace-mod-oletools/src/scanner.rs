//! olevba's `VBA_Scanner.scan(include_decoded_strings=True, deobfuscate=False)`.
//!
//! The patterns are Python's `re` on `str`, whose `\b` and `\w` differ from the regex crate's, so
//! they run over a fold: one byte per character, ASCII lowercased, with the characters Python's
//! IGNORECASE also takes for ASCII letters mapped to them, and any other character reduced to a word,
//! space or other class. `Dridex` is absent because `DridexUrlDecode` slices with a float on Python 3,
//! which raises, and detect_dridex_strings keeps nothing. `deobfuscate=False` leaves `vba_strings` empty.

use std::collections::HashSet;
use std::sync::OnceLock;

use base64::Engine;
use memchr::memmem;
use regex::Regex;
use regex::bytes::Regex as BytesRegex;

use crate::py::{is_space, is_word};
use crate::tables::{
    AUTOEXEC_KEYWORDS, AUTOEXEC_KEYWORDS_REGEX, SUSPICIOUS_KEYWORDS, SUSPICIOUS_KEYWORDS_REGEX,
};

const OTHER_WORD: u8 = 0x80;
const OTHER: u8 = 0x81;
const OTHER_SPACE: u8 = 0x82;

/// A kind, a value and a description, as `scan` returns them.
pub type ScanResult = (String, String, String);

struct Folded<'a> {
    text: &'a str,
    bytes: Vec<u8>,
    /// Each character's byte offset in text, and the length at the end. None when text is ASCII.
    offsets: Option<Vec<u32>>,
}

impl<'a> Folded<'a> {
    fn new(text: &'a str) -> Folded<'a> {
        let ascii = text.is_ascii();
        let mut bytes = Vec::with_capacity(text.len());
        let mut offsets = if ascii {
            None
        } else {
            Some(Vec::with_capacity(text.len() + 1))
        };
        for (at, c) in text.char_indices() {
            if let Some(offsets) = &mut offsets {
                offsets.push(at as u32);
            }
            bytes.push(fold(c));
        }
        if let Some(offsets) = &mut offsets {
            offsets.push(text.len() as u32);
        }
        Folded {
            text,
            bytes,
            offsets,
        }
    }

    fn slice(&self, start: usize, end: usize) -> &'a str {
        match &self.offsets {
            None => &self.text[start..end],
            Some(offsets) => &self.text[offsets[start] as usize..offsets[end] as usize],
        }
    }

    fn word_at(&self, at: usize) -> bool {
        self.bytes.get(at).is_some_and(|&byte| is_fold_word(byte))
    }

    /// `\b` at a position.
    fn boundary(&self, at: usize) -> bool {
        let before = at > 0 && self.word_at(at - 1);
        before != self.word_at(at)
    }
}

/// One character of the fold.
pub(crate) fn fold_char(c: char) -> u8 {
    fold(c)
}

fn fold(c: char) -> u8 {
    if c.is_ascii() {
        return (c as u8).to_ascii_lowercase();
    }
    match c {
        '\u{212A}' => b'k',
        '\u{17F}' => b's',
        '\u{130}' | '\u{131}' => b'i',
        c if is_space(c) => OTHER_SPACE,
        c if is_word(c) => OTHER_WORD,
        _ => OTHER,
    }
}

fn is_fold_word(byte: u8) -> bool {
    byte == OTHER_WORD || byte == b'_' || byte.is_ascii_alphanumeric()
}

fn is_fold_space(byte: u8) -> bool {
    byte == OTHER_SPACE || matches!(byte, 0x09..=0x0D | 0x1C..=0x20)
}

/// `re.search(r'(?i)\b' + re.escape(keyword) + r'\b', code)`.
fn search_literal(code: &Folded<'_>, lower: &str) -> Option<(usize, usize)> {
    let needle = lower.as_bytes();
    memmem::find_iter(&code.bytes, needle)
        .find(|&at| code.boundary(at) && code.boundary(at + needle.len()))
        .map(|at| (at, at + needle.len()))
}

/// `(?i)\b\w+_Suffix\b`. `\w+` starts a word, so the match is a whole word that ends in the suffix.
fn search_suffix(code: &Folded<'_>, suffix: &str) -> Option<(usize, usize)> {
    let needle = suffix.as_bytes();
    for at in memmem::find_iter(&code.bytes, needle) {
        let end = at + needle.len();
        if code.word_at(end) || at == 0 || !code.word_at(at - 1) {
            continue;
        }
        let mut start = at;
        while start > 0 && code.word_at(start - 1) {
            start -= 1;
        }
        return Some((start, end));
    }
    None
}

/// A literal, then what `tail` says may follow, in the order Python's backtracking tries it.
fn search_with_tails(code: &Folded<'_>, prefix: &str, tails: &[&str]) -> Option<(usize, usize)> {
    for at in memmem::find_iter(&code.bytes, prefix.as_bytes()) {
        if !code.boundary(at) {
            continue;
        }
        let after = at + prefix.len();
        for tail in tails {
            let end = after + tail.len();
            if code.bytes.get(after..end) == Some(tail.as_bytes()) && code.boundary(end) {
                return Some((at, end));
            }
        }
    }
    None
}

fn search_not_after(code: &Folded<'_>, literal: &str) -> Option<(usize, usize)> {
    const AFTER: &[u8] = b"could contain following functions: ";
    memmem::find_iter(&code.bytes, literal.as_bytes())
        .find(|&at| {
            code.boundary(at)
                && code.boundary(at + literal.len())
                && !(at >= AFTER.len() && &code.bytes[at - AFTER.len()..at] == AFTER)
        })
        .map(|at| (at, at + literal.len()))
}

/// `\.\s*Variables`, the one pattern that starts with something other than a word.
fn search_variables(code: &Folded<'_>) -> Option<(usize, usize)> {
    const NAME: &[u8] = b"variables";
    let mut from = 0;
    while let Some(found) = memchr::memchr(b'.', &code.bytes[from..]) {
        let at = from + found;
        from = at + 1;
        if !code.boundary(at) {
            continue;
        }
        let mut next = at + 1;
        while code
            .bytes
            .get(next)
            .is_some_and(|&byte| is_fold_space(byte))
        {
            next += 1;
        }
        let end = next + NAME.len();
        if code.bytes.get(next..end) == Some(NAME) && code.boundary(end) {
            return Some((at, end));
        }
    }
    None
}

/// `SUSPICIOUS_KEYWORDS_REGEX`'s patterns, each as `(?i)\b...\b` would match.
fn search_suspicious_regex(code: &Folded<'_>, pattern: &str) -> Option<(usize, usize)> {
    match pattern {
        r"\.\s*Variables" => search_variables(code),
        "EnumSystemLanguageGroupsW?" => {
            search_with_tails(code, "enumsystemlanguagegroups", &["w", ""])
        }
        "EnumDateFormats(?:W|(?:Ex){1,2})?" => {
            search_with_tails(code, "enumdateformats", &["w", "exex", "ex", ""])
        }
        "system" => search_literal(code, "system"),
        "popen" => search_literal(code, "popen"),
        "exec[lv][ep]?" => search_with_tails(code, "exec", &["le", "lp", "l", "ve", "vp", "v"]),
        "(?<!Could contain following functions: )EXEC" => search_not_after(code, "exec"),
        "(?<!Could contain following functions: )REGISTER" => search_not_after(code, "register"),
        "Could contain following functions: EXEC" => {
            search_literal(code, "could contain following functions: exec")
        }
        "Could contain following functions: REGISTER" => {
            search_literal(code, "could contain following functions: register")
        }
        other => unreachable!("a pattern with no port: {other}"),
    }
}

fn obfuscation_text(obfuscation: Option<&str>) -> String {
    obfuscation.map_or_else(String::new, |name| format!(" (obfuscation: {name})"))
}

fn detect_autoexec(code: &Folded<'_>, obfuscation: Option<&str>) -> Vec<(String, String)> {
    let suffix = obfuscation_text(obfuscation);
    let mut results = Vec::new();
    for (description, keywords) in AUTOEXEC_KEYWORDS {
        for keyword in *keywords {
            if let Some((start, end)) = search_literal(code, &keyword.to_ascii_lowercase()) {
                results.push((
                    code.slice(start, end).to_owned(),
                    format!("{description}{suffix}"),
                ));
            }
        }
    }
    for (description, keywords) in AUTOEXEC_KEYWORDS_REGEX {
        for keyword in *keywords {
            let literal = keyword
                .strip_prefix(r"\w+")
                .expect("each is \\w+_Name")
                .to_ascii_lowercase();
            if let Some((start, end)) = search_suffix(code, &literal) {
                results.push((
                    code.slice(start, end).to_owned(),
                    format!("{description}{suffix}"),
                ));
            }
        }
    }
    results
}

fn detect_suspicious(code: &Folded<'_>, obfuscation: Option<&str>) -> Vec<(String, String)> {
    let suffix = obfuscation_text(obfuscation);
    let mut results = Vec::new();
    for (description, keywords) in SUSPICIOUS_KEYWORDS {
        for keyword in *keywords {
            if let Some((start, end)) = search_literal(code, &keyword.to_ascii_lowercase()) {
                results.push((
                    code.slice(start, end).to_owned(),
                    format!("{description}{suffix}"),
                ));
            }
        }
    }
    for (description, keywords) in SUSPICIOUS_KEYWORDS_REGEX {
        for keyword in *keywords {
            if let Some((start, end)) = search_suspicious_regex(code, keyword) {
                results.push((
                    code.slice(start, end).to_owned(),
                    format!("{description}{suffix}"),
                ));
            }
        }
    }
    if code.text.contains('\u{8}') && obfuscation.is_none() {
        results.push((
            "\u{8}".to_owned(),
            "May use special characters such as backspace to obfuscate code when printed on the console".to_owned(),
        ));
    }
    results
}

const IPV4: &str = r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])";

fn url_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(&format!(
            r"(?:http|ftp)s?://(?:{IPV4}|(?:[a-zA-Z0-9\-\.]+\.(?:xn--[a-zA-Z0-9]{{4,20}}|[a-zA-Z]{{2,20}})))(?::[0-9]{{1,5}})?(?:/[a-zA-Z0-9\-\._\?,'/\\\+&%\$#=~]*)?"
        ))
        .expect("a valid pattern")
    })
}

fn ipv4_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(IPV4).expect("a valid pattern"))
}

/// On the fold, so lowercase only. Its last `\b` is a backspace in olevba, a string that isn't raw.
fn email_regex() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| {
        BytesRegex::new(&format!(
            r"(?-u)[a-z0-9._%+\-]+@(?:{IPV4}|(?:[a-z0-9\-\.]+\.(?:xn--[a-z0-9]{{4,20}}|[a-z]{{2,20}})))\x08"
        ))
        .expect("a valid pattern")
    })
}

const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "pif", "gadget", "msi", "msp", "msc", "vbs", "vbe", "vb", "jse", "js", "wsf", "wsc",
    "wsh", "ws", "bat", "cmd", "dll", "scr", "hta", "cpl", "class", "jar", "ps1xml", "ps1",
    "ps2xml", "ps2", "psc1", "psc2", "scf", "lnk", "inf", "reg",
];

fn detect_patterns(code: &Folded<'_>, obfuscation: Option<&str>) -> Vec<(String, String)> {
    let suffix = obfuscation_text(obfuscation);
    let mut results = Vec::new();
    let mut found: HashSet<String> = HashSet::new();
    let mut add = |kind: &str, value: &str| {
        let excluded = value.starts_with("http://schemas.openxmlformats.org/")
            || value.starts_with("http://schemas.microsoft.com/");
        if !found.contains(value) && !excluded {
            results.push((format!("{kind}{suffix}"), value.to_owned()));
            found.insert(value.to_owned());
        }
    };
    let text = code.text;
    let mut from = 0;
    while let Some(found) = url_regex().find_at(text, from) {
        if str_boundary(text, found.start()) {
            add("URL", found.as_str());
            from = found.end();
        } else {
            from = next_char(text, found.start());
        }
        if from > text.len() {
            break;
        }
    }
    for found in ipv4_regex().find_iter(text) {
        add("IPv4 address", found.as_str());
    }
    let mut from = 0;
    while let Some(found) = email_regex().find_at(&code.bytes, from) {
        if code.boundary(found.start()) {
            add("E-mail address", code.slice(found.start(), found.end()));
            from = found.end();
        } else {
            // only the next place \b holds can match, and the same characters then match
            from = found.start() + 1;
            while from < found.end() && !code.boundary(from) {
                from += 1;
            }
        }
    }
    // (?i)\b\w+\.(EXE|...)\b: \w+ starts a word and the extension is all of the word after the dot
    let bytes = &code.bytes;
    let mut at = 0;
    while at < bytes.len() {
        if !is_fold_word(bytes[at]) {
            at += 1;
            continue;
        }
        let mut end = at;
        while end < bytes.len() && is_fold_word(bytes[end]) {
            end += 1;
        }
        if bytes.get(end) == Some(&b'.') {
            let mut after = end + 1;
            while after < bytes.len() && is_fold_word(bytes[after]) {
                after += 1;
            }
            if EXECUTABLE_EXTENSIONS
                .iter()
                .any(|extension| extension.as_bytes() == &bytes[end + 1..after])
            {
                add("Executable file name", code.slice(at, after));
                at = after;
                continue;
            }
        }
        at = end;
    }
    results
}

fn str_boundary(text: &str, at: usize) -> bool {
    let before = text[..at].chars().next_back().is_some_and(is_word);
    let after = text[at..].chars().next().is_some_and(is_word);
    before != after
}

fn next_char(text: &str, at: usize) -> usize {
    at + text[at..].chars().next().map_or(1, char::len_utf8)
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => byte - b'A' + 10,
    }
}

fn unhexlify(text: &[u8]) -> Vec<u8> {
    text.as_chunks::<2>()
        .0
        .iter()
        .map(|pair| hex_value(pair[0]) << 4 | hex_value(pair[1]))
        .collect()
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn detect_hex_strings(code: &str) -> Vec<(String, String)> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new("(?:[0-9A-Fa-f]{2}){4,}").expect("a valid pattern"));
    let mut results = Vec::new();
    let mut found = HashSet::new();
    for hit in re.find_iter(code) {
        if found.insert(hit.as_str()) {
            results.push((
                hit.as_str().to_owned(),
                lossy(&unhexlify(hit.as_str().as_bytes())),
            ));
        }
    }
    results
}

fn detect_base64_strings(code: &str) -> Vec<(String, String)> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r#""(?:[A-Za-z0-9+/]{4}){1,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)?""#)
            .expect("a valid pattern")
    });
    const WHITELIST: &[&str] = &[
        "thisdocument",
        "thisworkbook",
        "test",
        "temp",
        "http",
        "open",
        "exit",
        "kernel32",
        "virtualalloc",
        "createthread",
    ];
    let mut results = Vec::new();
    let mut found = HashSet::new();
    for hit in re.find_iter(code) {
        let value = hit.as_str().trim_matches('"');
        let is_only_hex = !value
            .bytes()
            .any(|byte| matches!(byte, b'G'..=b'Z' | b'g'..=b'z'));
        if is_only_hex
            || found.contains(value)
            || WHITELIST.contains(&value.to_lowercase().as_str())
        {
            continue;
        }
        // the pattern only takes well-formed base64, whose padding the engine would refuse otherwise
        if let Ok(decoded) = base64::engine::general_purpose::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::general_purpose::GeneralPurposeConfig::new()
                .with_decode_allow_trailing_bits(true)
                .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
        )
        .decode(value)
        {
            results.push((value.to_owned(), lossy(&decoded)));
            found.insert(value);
        }
    }
    results
}

fn reversed(text: &str) -> String {
    text.chars().rev().collect()
}

/// `vba_collapse_long_lines`.
fn collapse_long_lines(code: &str) -> String {
    code.replace(" _\r\n", " ")
        .replace(" _\r", " ")
        .replace(" _\n", " ")
}

/// `VBA_Scanner(code).scan(True, False)`.
pub fn scan(code: &str) -> Vec<ScanResult> {
    let code = collapse_long_lines(code);
    let hex_strings = detect_hex_strings(&code);
    let has_reverse = code.to_lowercase().contains("strreverse");
    let (mut code_hex, mut code_hex_rev, mut code_rev_hex) =
        (String::new(), String::new(), String::new());
    for (encoded, decoded) in &hex_strings {
        code_hex.push('\n');
        code_hex.push_str(decoded);
        if has_reverse {
            code_hex_rev.push('\n');
            code_hex_rev.push_str(&reversed(decoded));
            code_rev_hex.push('\n');
            let reversed_hex: Vec<u8> = encoded.bytes().rev().collect();
            code_rev_hex.push_str(&lossy(&unhexlify(&reversed_hex)));
        }
    }
    let base64_strings = detect_base64_strings(&code);
    let mut code_base64 = String::new();
    for (_, decoded) in &base64_strings {
        code_base64.push('\n');
        code_base64.push_str(decoded);
    }

    let mut autoexec = Vec::new();
    let mut suspicious = Vec::new();
    let mut iocs = Vec::new();
    for (text, obfuscation) in [
        (code.as_str(), None),
        (code_hex.as_str(), Some("Hex")),
        (code_hex_rev.as_str(), Some("Hex+StrReverse")),
        (code_rev_hex.as_str(), Some("StrReverse+Hex")),
        (code_base64.as_str(), Some("Base64")),
    ] {
        let folded = Folded::new(text);
        autoexec.extend(detect_autoexec(&folded, obfuscation));
        suspicious.extend(detect_suspicious(&folded, obfuscation));
        iocs.extend(detect_patterns(&folded, obfuscation));
    }
    if !hex_strings.is_empty() {
        suspicious.push((
            "Hex Strings".to_owned(),
            "Hex-encoded strings were detected, may be used to obfuscate strings (option --decode to see all)".to_owned(),
        ));
    }
    if !base64_strings.is_empty() {
        suspicious.push((
            "Base64 Strings".to_owned(),
            "Base64-encoded strings were detected, may be used to obfuscate strings (option --decode to see all)".to_owned(),
        ));
    }

    let mut results = Vec::new();
    let mut seen = HashSet::new();
    for (keyword, description) in autoexec {
        if seen.insert(keyword.clone()) {
            results.push(("AutoExec".to_owned(), keyword, description));
        }
    }
    let mut seen = HashSet::new();
    for (keyword, description) in suspicious {
        if seen.insert(keyword.clone()) {
            results.push(("Suspicious".to_owned(), keyword, description));
        }
    }
    let mut seen = HashSet::new();
    for (kind, value) in iocs {
        if seen.insert(value.clone()) {
            results.push(("IOC".to_owned(), value, kind));
        }
    }
    for (encoded, decoded) in hex_strings {
        results.push(("Hex String".to_owned(), decoded, encoded));
    }
    for (encoded, decoded) in base64_strings {
        results.push(("Base64 String".to_owned(), decoded, encoded));
    }
    results
}

/// `filter_vba`.
pub fn filter_vba(code: &str) -> String {
    let lines = crate::py::splitlines(code);
    let start = lines
        .iter()
        .take_while(|line| line.starts_with("Attribute VB_") && !line.contains(':'))
        .count();
    lines[start..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keywords(code: &str) -> Vec<String> {
        scan(code).into_iter().map(|row| row.1).collect()
    }

    #[test]
    fn a_keyword_needs_pythons_word_boundaries() {
        assert_eq!(keywords("reShell"), Vec::<String>::new());
        assert_eq!(keywords("Shell \"x\""), ["Shell"]);
        // U+0301 is a mark, which Python's \w doesn't take and Rust's does
        assert_eq!(keywords("\u{301}Shell"), ["Shell"]);
        // the Kelvin sign folds to k under IGNORECASE
        assert_eq!(keywords("\u{212A}ill"), ["\u{212A}ill"]);
    }

    #[test]
    fn an_event_handler_is_a_whole_word() {
        assert_eq!(keywords("Button1_Click"), ["Button1_Click"]);
        assert!(keywords("Button1_Clicked").is_empty());
    }

    #[test]
    fn filter_vba_drops_only_leading_attributes_without_colons() {
        assert_eq!(
            filter_vba("Attribute VB_Name = \"A\"\r\nSub X()\r\n"),
            "Sub X()"
        );
        assert_eq!(
            filter_vba("Attribute VB_A: x\nAttribute VB_B\n"),
            "Attribute VB_A: x\nAttribute VB_B"
        );
    }
}
