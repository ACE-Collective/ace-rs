//! Run markers: ace3's `saq/svs/markers.py`. A marker is `svs-` followed by 26 base32 characters, 128 random
//! bits. A launcher puts its run's marker where the test's process telemetry shows it, and attribution finds
//! it in an alert. A marker isn't secret: it attributes an alert only when the alert agrees with its run.

use std::sync::LazyLock;

use regex::Regex;

pub const MARKER_PREFIX: &str = "svs-";
pub const MARKER_LENGTH: usize = MARKER_PREFIX.len() + 26;

const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The marker's body, case-insensitive since telemetry may change a command line's case. ace3's pattern
/// also requires that no `[a-z0-9]` comes right before or after it, so a marker inside a longer token isn't
/// one; the regex crate has no lookaround, so `find_markers` checks the neighbours. No marker can start
/// inside a candidate it rejects, since `-` isn't a base32 character.
static MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("(?i)svs-[a-z2-7]{26}").expect("a valid pattern"));
/// What may not touch a marker, case-insensitive as Python's `[a-z0-9]` under IGNORECASE is.
static NEIGHBOUR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("(?i)^[a-z0-9]$").expect("a valid pattern"));

/// A new random marker, lower case.
pub fn new_marker() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("the system has randomness");
    let mut marker = String::with_capacity(MARKER_LENGTH);
    marker.push_str(MARKER_PREFIX);
    // RFC 4648 base32 of 128 bits is 26 characters once its padding is gone
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            marker.push(BASE32[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        marker.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    marker
}

/// A marker as runs store it: trimmed and lower case.
pub fn normalize_marker(value: &str) -> String {
    ace_pycompat::pystr::strip(value).to_lowercase()
}

/// Whether `text` is one marker, as runs store it or in any case.
pub fn is_marker(text: &str) -> bool {
    text.len() == MARKER_LENGTH
        && MARKER
            .find(text)
            .is_some_and(|found| found.len() == text.len())
}

fn touches(c: Option<char>) -> bool {
    c.is_some_and(|c| {
        let mut buffer = [0u8; 4];
        NEIGHBOUR.is_match(c.encode_utf8(&mut buffer))
    })
}

/// The distinct markers in `text`, normalized, in the order they first appear.
pub fn find_markers(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for candidate in MARKER.find_iter(text) {
        let before = text[..candidate.start()].chars().next_back();
        let after = text[candidate.end()..].chars().next();
        if touches(before) || touches(after) {
            continue;
        }
        let marker = normalize_marker(candidate.as_str());
        if !found.contains(&marker) {
            found.push(marker);
        }
    }
    found
}

/// The markers in what the marker rule matched, which can hold a boundary character on each side and NULs
/// when the match was UTF-16 text: ace3's `find_markers_in_match`. Bytes are read as Latin-1, as ace3 reads
/// them.
pub fn find_markers_in_match(data: &[u8]) -> Vec<String> {
    let text: String = data
        .iter()
        .filter(|byte| **byte != 0)
        .map(|byte| char::from(*byte))
        .collect();
    find_markers(&text)
}

/// ace3's tests/saq/svs/test_markers.py.
#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn new_marker_format() {
        let marker = new_marker();
        assert!(marker.starts_with("svs-"));
        assert_eq!(marker.len(), MARKER_LENGTH);
        assert_eq!(MARKER_LENGTH, 30);
        assert_eq!(marker, marker.to_lowercase());
        assert!(is_marker(&marker));
        // the last character carries 3 bits and two zero bits of padding, as Python's b32encode
        assert!(matches!(
            marker.as_bytes()[29],
            b'a' | b'e' | b'i' | b'm' | b'q' | b'u' | b'y' | b'4'
        ));
    }

    #[test]
    fn markers_are_random() {
        let markers: BTreeSet<String> = (0..1000).map(|_| new_marker()).collect();
        assert_eq!(markers.len(), 1000);
    }

    #[test]
    fn find_markers_in_text() {
        let marker = new_marker();
        let text = format!(
            "powershell.exe \"& {{whoami}}\" <# {} #> & REM {marker}; other svs-{}",
            marker.to_uppercase(),
            "a".repeat(25)
        );
        assert_eq!(find_markers(&text), std::slice::from_ref(&marker));
        assert_eq!(find_markers(&format!("x{marker}")), Vec::<String>::new());
        assert_eq!(find_markers(&format!("{marker}a")), Vec::<String>::new());
        assert_eq!(find_markers(""), Vec::<String>::new());
        // a boundary that isn't a base32 neighbour is fine, and a marker's case is folded
        assert_eq!(
            find_markers(&format!("-{}.", marker.to_uppercase())),
            std::slice::from_ref(&marker)
        );
        // UTF-16 text as the marker rule matches it, read as Latin-1 with its NULs dropped
        let wide: Vec<u8> = format!(" {marker} ").bytes().flat_map(|b| [b, 0]).collect();
        assert_eq!(find_markers_in_match(&wide), [marker]);
    }

    #[test]
    fn normalize_a_marker() {
        assert_eq!(normalize_marker(" SVS-ABC "), "svs-abc");
    }
}
