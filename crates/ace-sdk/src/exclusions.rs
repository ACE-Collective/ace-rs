//! Global observable exclusions: observables no module analyzes, ace3's `observable_exclusions`.
//!
//! ace3 lists them in `etc/saq.default.yaml`, as a map of names to `<type>:<value>` specs, reads them
//! into `{type: [value]}` (`EngineConfiguration._get_observable_exclusions`, splitting each spec at its
//! first colon, so a value may hold one), and its executor drops an observable's work item before it
//! picks any module when the observable's `matches()` takes one of its type's values
//! (`AnalysisExecutor._process_observable_exclusions`). Here the core asks `Exclusions::excludes`
//! where it decides eligibility, so an excluded observable gets no task at all (`ace_core::orchestrator`).
//!
//! A value matches as ace3's observable classes match one:
//! - `ipv4`: a value with a `/` is a range by `iptools.IpRange` (`crate::iptools`), CIDR or a dotted
//!   netmask, and the observable matches when its address is in it; a range iptools can't read, or a
//!   value with no `/`, is compared exactly (`IPv4Observable.matches`).
//! - `ip`: a value with a `/` is a network by Python's `ipaddress.ip_network`, strict, so one with host
//!   bits set doesn't read; an address of the other IP version is never in it. Anything that doesn't
//!   read is compared exactly (`IPObservable.matches`).
//! - `mac_address`: the value is compared in the form producers write (`crate::layer2`), or as written
//!   when it isn't a mac address (`MacAddressObservable.matches`).
//! - Every other type: exactly, case and all (`Observable.matches`). `google.com` doesn't exclude
//!   `mail.google.com`.
//!
//! An exclusion applies to the type it names, not to a type that extends it, as ace3 looks its list up
//! by the observable's own type.
//!
//! The site overlay's `observable_exclusions:` is merged over ace3's defaults by name, as ace3 merges a
//! site's config over its `saq.default.yaml`: a new name adds an exclusion, one of ace3's names replaces
//! it, and a name set to null drops it. A spec without a colon stops the overlay from loading, where
//! ace3 logs it and goes on without it.

use std::collections::BTreeMap;

use ace_pycompat::ipaddress::{self, IpAddress};

use crate::iptools::IpRange;
use crate::layer2::normalize_mac_address;

/// ace3's `observable_exclusions:` in its `etc/saq.default.yaml`, by name.
pub const ACE3_OBSERVABLE_EXCLUSIONS: &[(&str, &str)] = &[
    // office365 journaling (blank user IDs)
    ("exclude_user", "user:-"),
    ("exclude_user_unknown", "user:unknown"),
    ("exclude_user_system", "user:system"),
    // loopback
    ("exclude_loopback", "ipv4:127.0.0.1"),
    ("exclude_invalid_ipv4", "ipv4:0.0.0.0"),
    // super common websites
    ("exclude_google", "fqdn:google.com"),
    ("exclude_youtube", "fqdn:youtube.com"),
];

/// The observables no module analyzes, as values by observable type.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exclusions {
    by_type: BTreeMap<String, Vec<String>>,
}

impl Exclusions {
    /// None at all.
    pub fn none() -> Exclusions {
        Exclusions::default()
    }

    /// ace3's defaults, the exclusions of a site whose overlay names none.
    pub fn ace3() -> Exclusions {
        Exclusions::from_section(&BTreeMap::new()).expect("ace3's specs read")
    }

    /// The overlay's `observable_exclusions:` over ace3's defaults. The error is the path of the spec
    /// that doesn't read and why.
    pub fn from_section(
        section: &BTreeMap<String, Option<String>>,
    ) -> Result<Exclusions, (String, String)> {
        let mut specs: BTreeMap<&str, &str> = ACE3_OBSERVABLE_EXCLUSIONS.iter().copied().collect();
        for (name, spec) in section {
            match spec {
                Some(spec) => specs.insert(name, spec),
                None => specs.remove(name.as_str()),
            };
        }
        let mut exclusions = Exclusions::none();
        for (name, spec) in specs {
            let Some((kind, value)) = spec.split_once(':') else {
                return Err((
                    format!("observable_exclusions.{name}"),
                    format!("{spec:?} isn't <type>:<value>"),
                ));
            };
            if kind.is_empty() {
                return Err((
                    format!("observable_exclusions.{name}"),
                    format!("{spec:?} names no observable type"),
                ));
            }
            exclusions.add(kind, value);
        }
        Ok(exclusions)
    }

    /// Excludes `value` of type `kind`, once.
    pub fn add(&mut self, kind: &str, value: &str) {
        let values = self.by_type.entry(kind.to_owned()).or_default();
        if !values.iter().any(|v| v == value) {
            values.push(value.to_owned());
        }
    }

    pub fn is_empty(&self) -> bool {
        self.by_type.is_empty()
    }

    /// Each type and its excluded values.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[String])> {
        self.by_type
            .iter()
            .map(|(kind, values)| (kind.as_str(), values.as_slice()))
    }

    /// Whether an observable of type `kind` and `value` is excluded.
    pub fn excludes(&self, kind: &str, value: &str) -> bool {
        self.by_type
            .get(kind)
            .is_some_and(|values| values.iter().any(|v| matches(kind, value, v)))
    }
}

/// ace3's `observable.matches(exclusion)` for an observable of type `kind` whose value is `value`.
fn matches(kind: &str, value: &str, exclusion: &str) -> bool {
    match kind {
        "ipv4" if exclusion.contains('/') => {
            // `self.value in iptools.IpRange(value)`; what raises falls through to the exact compare
            if let Some(found) = IpRange::new(exclusion).and_then(|range| range.contains(value)) {
                return found;
            }
            value == exclusion
        }
        "ip" if exclusion.contains('/') => {
            // `self._ip_address in ip_network(value)`, or the exact compare when that raises
            match (ipaddress::ip_address(value), ip_network(exclusion)) {
                (Ok(address), Some(network)) => network.contains(&address),
                _ => value == exclusion,
            }
        }
        "mac_address" => {
            normalize_mac_address(exclusion)
                .as_deref()
                .unwrap_or(exclusion)
                == value
        }
        _ => value == exclusion,
    }
}

/// A network as Python's `ip_network` reads it: the version, its address and its netmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Network {
    v4: bool,
    address: u128,
    netmask: u128,
}

impl Network {
    /// `address in network`: never for the other version.
    fn contains(&self, address: &IpAddress) -> bool {
        let (v4, ip) = match address {
            IpAddress::V4(a) => (true, u128::from(a.ip)),
            IpAddress::V6(a) => (false, a.ip),
        };
        v4 == self.v4 && ip & self.netmask == self.address
    }
}

/// Python's `ipaddress.ip_network(spec)`, strict: `IPv4Network`, then `IPv6Network`. None where both
/// raise.
fn ip_network(spec: &str) -> Option<Network> {
    let parts: Vec<&str> = spec.split('/').collect();
    if parts.len() > 2 {
        return None;
    }
    let (address, prefix) = (parts[0], parts.get(1).copied());
    if let Ok(a) = ipaddress::ipv4_address(address) {
        let prefix = match prefix {
            None => Some(32),
            Some(p) => prefix_from_string(p, 32).or_else(|| prefix_from_v4_mask(p)),
        };
        // IPv6Network can't read an IPv4 address either
        return network(true, u128::from(a.ip), prefix?, 32);
    }
    let a = ipaddress::ipv6_address(address).ok()?;
    let prefix = match prefix {
        None => 128,
        Some(p) => prefix_from_string(p, 128)?,
    };
    network(false, a.ip, prefix, 128)
}

/// The network of `address` with `prefix` bits, or None when strict mode refuses it: it has host bits
/// set.
fn network(v4: bool, address: u128, prefix: u32, max: u32) -> Option<Network> {
    let netmask = mask(prefix, max);
    (address & netmask == address).then_some(Network {
        v4,
        address,
        netmask,
    })
}

fn mask(prefix: u32, max: u32) -> u128 {
    let all = if max == 128 {
        u128::MAX
    } else {
        (1u128 << max) - 1
    };
    if prefix == 0 {
        0
    } else {
        (all >> (max - prefix)) << (max - prefix)
    }
}

/// `_prefix_from_prefix_string`: ASCII digits, at most `max`.
fn prefix_from_string(text: &str, max: u32) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u32>().ok().filter(|p| *p <= max)
}

/// IPv4's `_prefix_from_ip_string`: a netmask, then a hostmask.
fn prefix_from_v4_mask(text: &str) -> Option<u32> {
    let ip = ipaddress::ipv4_address(text).ok()?.ip;
    prefix_from_v4_int(ip).or_else(|| prefix_from_v4_int(!ip))
}

/// `_prefix_from_ip_int`: ones, then zeros.
fn prefix_from_v4_int(ip: u32) -> Option<u32> {
    let zeros = ip.trailing_zeros().min(32);
    let prefix = 32 - zeros;
    let ones = if zeros == 32 { 0 } else { ip >> zeros };
    let all = if prefix == 32 {
        u32::MAX
    } else {
        (1u32 << prefix) - 1
    };
    (ones == all).then_some(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn of(pairs: &[(&str, Option<&str>)]) -> Result<Exclusions, (String, String)> {
        Exclusions::from_section(
            &pairs
                .iter()
                .map(|(name, spec)| ((*name).to_owned(), spec.map(str::to_owned)))
                .collect(),
        )
    }

    fn only(kind: &str, values: &[&str]) -> Exclusions {
        let mut exclusions = Exclusions::none();
        for value in values {
            exclusions.add(kind, value);
        }
        exclusions
    }

    /// ace3's defaults, as `test_engine_configuration_observable_exclusions` reads them.
    #[test]
    fn ace3_s_defaults() {
        let exclusions = Exclusions::ace3();
        let by_type: BTreeMap<&str, Vec<&str>> = exclusions
            .iter()
            .map(|(kind, values)| (kind, values.iter().map(String::as_str).collect()))
            .collect();
        assert_eq!(
            by_type,
            BTreeMap::from([
                ("fqdn", vec!["google.com", "youtube.com"]),
                ("ipv4", vec!["0.0.0.0", "127.0.0.1"]),
                ("user", vec!["-", "system", "unknown"]),
            ])
        );
        assert!(exclusions.excludes("fqdn", "youtube.com"));
        assert!(exclusions.excludes("user", "-"));
        assert!(!exclusions.excludes("fqdn", "www.youtube.com"));
        assert!(!exclusions.excludes("url", "google.com"));
    }

    /// The overlay adds, replaces and drops by name, and a spec splits at its first colon only
    /// (`test_engine_configuration_observable_exclusions_override`, `_deduplicated`, `_malformed`).
    #[test]
    fn the_overlay_merges_over_ace3_s() {
        let exclusions = of(&[
            ("exclude_google", None),
            ("exclude_youtube", Some("fqdn:example.com")),
            ("again", Some("fqdn:example.com")),
            ("a_url", Some("url:https://a.example/x?y=1")),
        ])
        .expect("reads");
        assert!(!exclusions.excludes("fqdn", "google.com"));
        assert!(!exclusions.excludes("fqdn", "youtube.com"));
        assert!(exclusions.excludes("fqdn", "example.com"));
        assert_eq!(
            exclusions
                .iter()
                .find(|(k, _)| *k == "fqdn")
                .map(|(_, v)| v.len()),
            Some(1),
            "a value listed twice is kept once"
        );
        assert!(exclusions.excludes("url", "https://a.example/x?y=1"));
        assert!(
            exclusions.excludes("ipv4", "127.0.0.1"),
            "the rest of ace3's stay"
        );
        assert_eq!(
            of(&[("bad", Some("google.com"))]),
            Err((
                "observable_exclusions.bad".to_owned(),
                "\"google.com\" isn't <type>:<value>".to_owned()
            ))
        );
        assert!(of(&[("bad", Some(":google.com"))]).is_err());
    }

    /// test_executor_observable_exclusions.py: exact, not a substring and not a subdomain.
    #[test]
    fn values_match_exactly() {
        let exclusions = only("fqdn", &["google.com"]);
        assert!(exclusions.excludes("fqdn", "google.com"));
        assert!(!exclusions.excludes("fqdn", "oogle.com"));
        assert!(!exclusions.excludes("fqdn", "mail.google.com"));
        assert!(!exclusions.excludes("fqdn", "Google.com"));
        assert!(!only("url", &["google.com"]).excludes("fqdn", "google.com"));
    }

    /// `IPv4Observable.matches`: iptools' ranges, and exact otherwise.
    #[test]
    fn ipv4_matches_ranges_as_iptools_reads_them() {
        let exclusions = only(
            "ipv4",
            &["10.0.0.0/8", "192.168.1.0/255.255.255.0", "127.0.0.1"],
        );
        assert!(exclusions.excludes("ipv4", "10.1.2.3"));
        assert!(exclusions.excludes("ipv4", "192.168.1.200"));
        assert!(exclusions.excludes("ipv4", "127.0.0.1"));
        assert!(!exclusions.excludes("ipv4", "192.168.2.1"));
        assert!(!exclusions.excludes("ipv4", "11.0.0.1"));
        // a range iptools can't read is compared as written
        assert!(only("ipv4", &["10.0.0.0/33"]).excludes("ipv4", "10.0.0.0/33"));
    }

    /// `IPObservable.matches`: `ip_network`, strict, and exact when it raises.
    #[test]
    fn ip_matches_networks_as_python_reads_them() {
        let exclusions = only(
            "ip",
            &["10.0.0.0/8", "2001:db8::/32", "192.168.0.0/0.0.255.255"],
        );
        assert!(exclusions.excludes("ip", "10.200.0.1"));
        assert!(exclusions.excludes("ip", "2001:db8::5"));
        assert!(exclusions.excludes("ip", "192.168.3.4"));
        assert!(!exclusions.excludes("ip", "11.0.0.1"));
        assert!(
            !exclusions.excludes("ip", "::ffff:10.0.0.1"),
            "another version"
        );
        // host bits set: strict refuses it, so only the same text matches
        let host_bits = only("ip", &["10.0.0.1/8"]);
        assert!(!host_bits.excludes("ip", "10.0.0.1"));
        assert!(host_bits.excludes("ip", "10.0.0.1/8"));
        assert_eq!(
            ip_network("10.0.0.0/255.0.0.0").map(|n| n.netmask),
            Some(0xff00_0000)
        );
        assert_eq!(ip_network("0.0.0.0/0").map(|n| n.netmask), Some(0));
        assert_eq!(ip_network("10.0.0.0/+8"), None);
        assert_eq!(ip_network("10.0.0.0/8/8"), None);
        assert_eq!(ip_network("2001:db8::/ffff::"), None);
    }

    /// `MacAddressObservable.matches`: in any notation.
    #[test]
    fn mac_addresses_match_in_any_notation() {
        let exclusions = only("mac_address", &["00:50:56:C0:00:08"]);
        assert!(exclusions.excludes("mac_address", "00-50-56-c0-00-08"));
        assert!(!exclusions.excludes("mac_address", "00-50-56-c0-00-09"));
        assert!(only("mac_address", &["nonsense"]).excludes("mac_address", "nonsense"));
    }
}
