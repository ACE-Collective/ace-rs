//! `html.entities.html5`, and `html.unescape`'s handling of a numeric reference. The tables are the
//! ones Python 3.14 ships, generated from it (`tables/entities.py`). `html5` keys keep their `;`.

use crate::tables::entities::{HTML5, INVALID_CHARREFS, INVALID_CODEPOINTS};

/// `html5[name]`.
pub fn html5(name: &str) -> Option<&'static str> {
    HTML5
        .binary_search_by(|(key, _)| (*key).cmp(name))
        .ok()
        .map(|index| HTML5[index].1)
}

/// `html.unescape("&#...")`'s result, for `digits` with their `x` if they're hexadecimal.
pub fn numeric(digits: &str) -> String {
    let parsed = match digits.strip_prefix(['x', 'X']) {
        Some(hex) => saturating(hex, 16),
        None => saturating(digits, 10),
    };
    if let Ok(index) = INVALID_CHARREFS.binary_search_by(|(key, _)| key.cmp(&parsed)) {
        return INVALID_CHARREFS[index].1.to_owned();
    }
    if (0xD800..=0xDFFF).contains(&parsed) || parsed > 0x10FFFF {
        return "\u{fffd}".to_owned();
    }
    if INVALID_CODEPOINTS
        .iter()
        .any(|(low, high)| (*low..=*high).contains(&parsed))
    {
        return String::new();
    }
    char::from_u32(parsed).map(String::from).unwrap_or_default()
}

fn saturating(digits: &str, radix: u32) -> u32 {
    digits.chars().fold(0_u32, |value, c| {
        value
            .saturating_mul(radix)
            .saturating_add(c.to_digit(radix).unwrap_or(0))
    })
}
