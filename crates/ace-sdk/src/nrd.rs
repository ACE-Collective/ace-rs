//! The newly registered domains list's names (PLAN.md 7.4), normalized as ace3's `saq/nrd/` does:
//! a line of a feed with `normalize_line` (`refresh._normalize_domain`), and a value the analyzer
//! asks about with `normalize_lookup`, `candidates` and `registrable_domain` (`util._normalize`,
//! `util._candidate_domains`, `util.registrable_domain`). Both encode a Unicode name as Python's
//! `idna` package does (`idna_encode`). The core reads the list with these (`ace_core::nrd`), and
//! the module finds the domain it asks RDAP about.

/// Python's `str.isspace`, which `strip()` strips: Unicode's white space and the four information
/// separators, U+001C to U+001F.
fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn py_strip(value: &str) -> &str {
    value.trim_matches(py_space)
}

/// `saq.nrd.refresh._DOMAIN_LINE_RE`: `^[A-Za-z0-9.-]{1,253}$`.
fn ldh_line(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// `saq.nrd.refresh._normalize_domain`: what the list keeps of one line of a feed, or None for a
/// blank line, a comment or a line that isn't a domain.
pub fn normalize_line(line: &str) -> Option<String> {
    let lowered = py_strip(line).to_lowercase();
    let domain = lowered.trim_end_matches('.');
    if domain.is_empty() || domain.starts_with('#') {
        return None;
    }
    // ASCII LDH is kept as it is, so an A-label strict IDNA would refuse, such as an emoji
    // domain's, stays in the list
    let encoded = if ldh_line(domain) {
        domain.to_owned()
    } else {
        let encoded = idna_encode(domain)?;
        if !ldh_line(&encoded) {
            return None;
        }
        encoded
    };
    // a domain's last label is its TLD, never all digits
    let labels: Vec<&str> = encoded.split('.').collect();
    let last = labels.last().copied().unwrap_or_default();
    if labels.len() < 2 || (!last.is_empty() && last.chars().all(|c| c.is_ascii_digit())) {
        return None;
    }
    Some(encoded)
}

/// `saq.nrd.util._normalize`: the host of an http or https URL, or the value itself, stripped,
/// lowercased, without a trailing dot and IDNA-encoded; empty when nothing's left or the
/// encoding fails.
pub fn normalize_lookup(value: &str) -> String {
    let target = lookup_target(value);
    if target.is_empty() {
        return String::new();
    }
    let lowered = py_strip(&target).to_lowercase();
    let domain = lowered.trim_end_matches('.');
    if domain.is_empty() {
        return String::new();
    }
    idna_encode(domain).unwrap_or_default()
}

/// `saq.nrd.util._extract_lookup_target`: the hostname when the value parses as an http or https
/// URL with one, as `urlparse` reads it, and otherwise the value, stripped.
fn lookup_target(value: &str) -> String {
    let stripped = py_strip(value);
    if stripped.is_empty() {
        return String::new();
    }
    match url_host(stripped) {
        Some(host) => host,
        None => stripped.to_owned(),
    }
}

/// The hostname Python's `urlparse(value).hostname` gives when the scheme is http or https, or
/// None. A value urlparse refuses (a bracket that doesn't close) is None, as ace3 then looks the
/// value up as it is.
fn url_host(value: &str) -> Option<String> {
    // urlsplit strips leading C0 controls and spaces and removes tabs and newlines anywhere
    let cleaned: String = value
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let colon = cleaned.find(':')?;
    let scheme = &cleaned[..colon];
    let first = scheme.chars().next()?;
    if !first.is_ascii_alphabetic()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return None;
    }
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let rest = &cleaned[colon + 1..];
    let after = rest.strip_prefix("//")?;
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let netloc = &after[..end];
    if netloc.contains('[') != netloc.contains(']') {
        return None;
    }
    let host_port = netloc.rsplit_once('@').map_or(netloc, |(_, host)| host);
    let host = if let Some(open) = host_port.find('[') {
        let inside = &host_port[open + 1..];
        let close = inside.find(']')?;
        let bracketed = &inside[..close];
        // urlsplit checks a bracketed host is an IPv6 address (or IPvFuture)
        if !bracketed.starts_with('v') && bracketed.parse::<std::net::Ipv6Addr>().is_err() {
            return None;
        }
        bracketed.to_owned()
    } else {
        host_port
            .split_once(':')
            .map_or(host_port, |(host, _)| host)
            .to_owned()
    };
    let host = host.to_lowercase();
    (!host.is_empty()).then_some(host)
}

/// `saq.nrd.util._candidate_domains`: the normalized name and each parent of it down to its
/// registrable domain (eTLD+1), or the name alone when the public suffix list knows no suffix
/// for it.
pub fn candidates(normalized: &str) -> Vec<String> {
    let Some(registrable) = registrable_of(normalized) else {
        return vec![normalized.to_owned()];
    };
    let mut candidates = Vec::new();
    let mut current = normalized;
    loop {
        candidates.push(current.to_owned());
        if current == registrable {
            break;
        }
        match current.split_once('.') {
            Some((_, rest)) if !rest.is_empty() => current = rest,
            _ => break,
        }
    }
    candidates
}

/// tldextract's `top_domain_under_public_suffix` of a normalized (A-label) name. tldextract
/// matches the list in Unicode, so an A-label is decoded for the match and the registrable
/// domain is the same number of labels of the name.
fn registrable_of(normalized: &str) -> Option<String> {
    let unicode: Vec<String> = normalized
        .split('.')
        .map(|label| {
            label
                .strip_prefix("xn--")
                .and_then(idna::punycode::decode_to_string)
                .unwrap_or_else(|| label.to_owned())
        })
        .collect();
    let top = crate::domains::top_domain_under_public_suffix(&unicode.join("."))?;
    let count = top.split('.').count();
    let labels: Vec<&str> = normalized.split('.').collect();
    (count <= labels.len()).then(|| labels[labels.len() - count..].join("."))
}

/// `saq.nrd.util.registrable_domain`: the registrable domain RDAP is asked about, or the
/// normalized value when there's none; empty when the value doesn't normalize.
pub fn registrable_domain(value: &str) -> String {
    let normalized = normalize_lookup(value);
    if normalized.is_empty() {
        return normalized;
    }
    registrable_of(&normalized).unwrap_or(normalized)
}

/// Python `idna.encode(domain)` (IDNA 2008, idna 3.x): each label checked and Punycode-encoded,
/// None where it raises. `domain` is lowercase with no trailing dot.
///
/// RFC 5892's derived property is computed from the general category and NFKC here, where the
/// `idna` package has tables generated from it, and the joiner and context rules (CONTEXTJ,
/// CONTEXTO) and the bidi rule are refused rather than checked, so a label that needs one of them
/// is refused where ace3 might accept it (`crates/ace-mod-nrd/tests/differences.md`).
pub fn idna_encode(domain: &str) -> Option<String> {
    if domain.is_empty() {
        return None;
    }
    let mut labels = Vec::new();
    for label in domain.split('.') {
        labels.push(alabel(label)?);
    }
    let encoded = labels.join(".");
    // valid_string_length: 253 octets without a trailing dot
    (encoded.len() <= 253).then_some(encoded)
}

/// idna's `alabel`.
fn alabel(label: &str) -> Option<String> {
    if label.is_empty() {
        return None;
    }
    if label.is_ascii() {
        // `ulabel` of the ASCII bytes: an A-label must decode to a valid U-label
        let lowered = label.to_ascii_lowercase();
        if let Some(puny) = lowered.strip_prefix("xn--") {
            let decoded = idna::punycode::decode_to_string(puny)?;
            if decoded.is_empty() || decoded.is_ascii() {
                return None;
            }
            check_label(&decoded)?;
            // ulabel re-encodes it and wants the same A-label back
            if idna::punycode::encode_str(&decoded)? != puny {
                return None;
            }
        } else {
            check_label(&lowered)?;
        }
        return (label.len() <= 63).then(|| label.to_owned());
    }
    check_label(label)?;
    let encoded = format!("xn--{}", idna::punycode::encode_str(label)?);
    (encoded.len() <= 63).then_some(encoded)
}

/// idna's `check_label`: NFC, hyphens, no leading combining mark, and every code point PVALID.
fn check_label(label: &str) -> Option<()> {
    use unicode_normalization::UnicodeNormalization;
    if label.is_empty() || label.nfc().collect::<String>() != label {
        return None;
    }
    // check_hyphen_ok
    if label.get(2..4) == Some("--") || label.starts_with('-') || label.ends_with('-') {
        return None;
    }
    let first = label.chars().next()?;
    if matches!(
        unicode_general_category::get_general_category(first),
        unicode_general_category::GeneralCategory::NonspacingMark
            | unicode_general_category::GeneralCategory::SpacingMark
            | unicode_general_category::GeneralCategory::EnclosingMark
    ) {
        return None;
    }
    label.chars().all(pvalid).then_some(())
}

/// RFC 5892's PVALID, from its rules in order: the exceptions, LDH, then a code point is PVALID
/// when NFKC with case folding leaves it as it is, it isn't ignorable, and it's a letter, a digit
/// or a mark (`LetterDigits`).
fn pvalid(c: char) -> bool {
    use unicode_general_category::GeneralCategory as G;
    use unicode_normalization::UnicodeNormalization;
    match c {
        // Exceptions (F): PVALID
        '\u{df}' | '\u{3c2}' | '\u{6fd}' | '\u{6fe}' | '\u{f0b}' | '\u{3007}' => return true,
        // Exceptions: DISALLOWED, and CONTEXTO, which isn't checked
        '\u{640}' | '\u{7fa}' | '\u{302e}' | '\u{302f}' | '\u{3031}'..='\u{3035}' | '\u{303b}' => {
            return false;
        }
        '\u{b7}' | '\u{375}' | '\u{5f3}' | '\u{5f4}' | '\u{30fb}' => return false,
        '\u{660}'..='\u{669}' | '\u{6f0}'..='\u{6f9}' => return false,
        // CONTEXTJ, which isn't checked
        '\u{200c}' | '\u{200d}' => return false,
        _ => {}
    }
    if c.is_ascii() {
        return c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
    }
    // Unstable: NFKC(casefold(NFKC(c))) != c
    let once: String = std::iter::once(c).nfkc().collect();
    let folded: String = once.to_lowercase().nfkc().collect();
    if folded.chars().ne(std::iter::once(c)) {
        return false;
    }
    // IgnorableProperties: white space, the default ignorable marks and noncharacters
    let code = c as u32;
    if c.is_whitespace()
        || code == 0x34f
        || (0x180b..=0x180f).contains(&code)
        || (0xfe00..=0xfe0f).contains(&code)
        || (0xe0100..=0xe01ef).contains(&code)
        || (0xfdd0..=0xfdef).contains(&code)
        || code & 0xfffe == 0xfffe
    {
        return false;
    }
    // IgnorableBlocks: Combining Diacritical Marks for Symbols, Musical Symbols, Ancient Greek
    // Musical Notation; and OldHangulJamo
    if (0x20d0..=0x20ff).contains(&code)
        || (0x1d100..=0x1d1ff).contains(&code)
        || (0x1d200..=0x1d24f).contains(&code)
        || (0x1100..=0x11ff).contains(&code)
        || (0xa960..=0xa97f).contains(&code)
        || (0xd7b0..=0xd7ff).contains(&code)
    {
        return false;
    }
    matches!(
        unicode_general_category::get_general_category(c),
        G::LowercaseLetter
            | G::UppercaseLetter
            | G::OtherLetter
            | G::DecimalNumber
            | G::ModifierLetter
            | G::NonspacingMark
            | G::SpacingMark
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn reference() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/ace3/dumps/reference/nrd/reference.json");
        serde_json::from_str(&std::fs::read_to_string(path).expect("the reference reads"))
            .expect("JSON")
    }

    /// Every value of tools/ace3/dumps/fixtures/nrd/lookups.json normalizes, walks its parents and
    /// reduces to its registrable domain as ace3's saq.nrd.util did.
    #[test]
    fn lookups_normalize_as_ace3_s_util_does() {
        let reference = reference();
        let mut wrong = Vec::new();
        for case in reference["lookups"].as_array().expect("lookups") {
            let value = case["value"].as_str().expect("a value");
            let normalized = normalize_lookup(value);
            let got = serde_json::json!({
                "value": value,
                "normalized": normalized,
                "candidates": if normalized.is_empty() { vec![] } else { candidates(&normalized) },
                "registrable_domain": registrable_domain(value),
            });
            if &got != case {
                wrong.push(format!("ace3 {case}\nace-rs {got}"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// Every line of the fixture lists is kept, or dropped, as ace3's refresh did.
    #[test]
    fn list_lines_normalize_as_ace3_s_refresh_does() {
        let reference = reference();
        let mut wrong = Vec::new();
        for case in reference["lines"].as_array().expect("lines") {
            let line = case["line"].as_str().expect("a line");
            let kept = normalize_line(line);
            if kept.as_deref() != case["kept"].as_str() {
                wrong.push(format!("{line:?}: ace3 {} ace-rs {kept:?}", case["kept"]));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn idna_encodes_as_python_s_idna_package() {
        assert_eq!(
            idna_encode("bücher.com").as_deref(),
            Some("xn--bcher-kva.com")
        );
        assert_eq!(
            idna_encode("xn--bcher-kva.com").as_deref(),
            Some("xn--bcher-kva.com")
        );
        // a full-width letter changes under NFKC; ß is an exception, valid as it is
        assert_eq!(idna_encode("ａ.com"), None);
        assert_eq!(
            idna_encode("straße.de").as_deref(),
            Some("xn--strae-oqa.de")
        );
        // an A-label that doesn't decode, or decodes to ASCII
        assert_eq!(idna_encode("xn--a.com"), None);
        assert_eq!(idna_encode("a.b..c"), None);
        assert_eq!(idna_encode(&format!("{}.com", "a".repeat(64))), None);
        assert_eq!(idna_encode("a\u{200d}b.com"), None);
    }
}
