//! ace3's `saq/observables/network/layer2.py`: how a mac address is written. The core keeps a
//! `mac_address` observable in this form (`crate::observable_rules`), and a global exclusion of one
//! is compared in it (`crate::exclusions`), so the same card is the same value whichever separator
//! wrote it.

use ace_pycompat::pystr;

/// ace3's `normalize_mac_address` (`saq/observables/network/layer2.py`): six pairs of hex digits
/// with anything but hex digits between them, as `aa-bb-cc-dd-ee-ff`, lowercase; None for anything
/// else.
pub fn normalize_mac_address(value: &str) -> Option<String> {
    let mut pairs: Vec<String> = Vec::new();
    let mut chars = pystr::strip(value).chars().peekable();
    while pairs.len() < 6 {
        let (Some(a), Some(b)) = (chars.next(), chars.next()) else {
            return None;
        };
        if !a.is_ascii_hexdigit() || !b.is_ascii_hexdigit() {
            return None;
        }
        pairs.push(format!("{a}{b}").to_ascii_lowercase());
        // `[^a-fA-F0-9]*?` between pairs and after the last
        while chars.peek().is_some_and(|c| !c.is_ascii_hexdigit()) {
            chars.next();
        }
    }
    chars.next().is_none().then(|| pairs.join("-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_addresses_are_normalized_as_ace3_does() {
        let mac = |v| normalize_mac_address(v);
        assert_eq!(
            mac("02:00:00:AA:00:01").as_deref(),
            Some("02-00-00-aa-00-01")
        );
        assert_eq!(
            mac(" 0200.00aa.0001 ").as_deref(),
            Some("02-00-00-aa-00-01")
        );
        assert_eq!(
            mac("02:00:00:aa:00:01:").as_deref(),
            Some("02-00-00-aa-00-01")
        );
        assert_eq!(mac("02:00:00:aa:00"), None);
        assert_eq!(mac("02:00:00:aa:00:01:02"), None);
        assert_eq!(mac("0:200:00:aa:00:01"), None);
    }
}
