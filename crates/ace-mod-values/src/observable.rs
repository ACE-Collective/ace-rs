//! What ace3's observable classes do to a value these modules add (`saq/observables/`): some
//! refuse it, so `add_observable_by_spec` returns None and the module goes on without it, and some
//! change it. ace3's registry also refuses any value that is empty or only whitespace.

use ace_pycompat::pystr;
use ace_results::{NewObservable, ObservableKind};

/// `add_observable_by_spec(kind, value)`: the observable ace3 would add, or None where it refuses
/// the value.
pub fn new(kind: ObservableKind, value: &str) -> Option<NewObservable> {
    let value = normalize(kind, value)?;
    if pystr::strip(&value).is_empty() {
        return None;
    }
    Some(NewObservable::new(kind, value))
}

fn normalize(kind: ObservableKind, value: &str) -> Option<String> {
    let strip = |v: &str| pystr::strip(v).to_owned();
    if kind == ObservableKind::Fqdn {
        // FQDNObservable: validators.domain on the value as given, then stripped
        return ace_pycompat::validators::domain(value).then(|| strip(value));
    }
    if kind == ObservableKind::Ip {
        let v = strip(value);
        return ace_pycompat::ipaddress::ip_address(&v).is_ok().then_some(v);
    }
    if kind == ObservableKind::Url {
        return ace_mod_urls::url_extraction::names_a_host(value).then(|| value.to_owned());
    }
    if kind == ObservableKind::User {
        // UserObservable: stripped, and only what follows its last backslash
        let v = strip(value);
        return Some(v.rsplit('\\').next().unwrap_or_default().to_owned());
    }
    if kind == ObservableKind::FileLocation {
        // FileLocationObservable: a host and a path, split at the first @
        let (host, path) = value.split_once('@')?;
        return (!pystr::strip(host).is_empty() && !pystr::strip(path).is_empty())
            .then(|| value.to_owned());
    }
    if kind == ObservableKind::MacAddress {
        // MacAddressObservable: six pairs of hex digits, lowercase, joined by `-`
        return normalize_mac_address(value);
    }
    if [
        ObservableKind::Hostname,
        ObservableKind::Asset,
        ObservableKind::UriPath,
        ObservableKind::UserAgent,
    ]
    .contains(&kind)
    {
        return Some(strip(value));
    }
    // file_path, file_name: stored as given
    Some(value.to_owned())
}

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

    #[test]
    fn values_are_refused_or_changed_as_ace3_does() {
        let value = |k, v: &str| new(k, v).map(|o| o.value);
        assert_eq!(value(ObservableKind::Fqdn, "@x.com"), None);
        assert_eq!(
            value(ObservableKind::Fqdn, "m\u{fc}nchen.de").as_deref(),
            Some("m\u{fc}nchen.de")
        );
        assert_eq!(
            value(ObservableKind::User, r" DOM\bob ").as_deref(),
            Some("bob")
        );
        assert_eq!(value(ObservableKind::User, "  "), None);
        assert_eq!(
            value(ObservableKind::Hostname, " HOST ").as_deref(),
            Some("HOST")
        );
        assert_eq!(value(ObservableKind::FileLocation, "h@ "), None);
        assert_eq!(
            value(ObservableKind::FilePath, " C:\\x").as_deref(),
            Some(" C:\\x")
        );
        assert_eq!(
            value(ObservableKind::Ip, "10.0.0.1 ").as_deref(),
            Some("10.0.0.1")
        );
        assert_eq!(value(ObservableKind::Ip, "10.0.0"), None);
        assert_eq!(value(ObservableKind::Url, "https:.."), None);
    }
}
