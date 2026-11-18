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
        return ace_sdk::layer2::normalize_mac_address(value);
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

#[cfg(test)]
mod tests {
    use super::*;

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
