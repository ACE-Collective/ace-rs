//! The observables a capture's index holds, each in the category whose result adds it, and how the
//! results share each type's `MAX_OBSERVABLES_PER_TYPE` (ace3's `collect_observables` and
//! `add_pcap_observables`).
//!
//! ace3 counts what every pcap analysis of the capture already holds when it adds more, so the
//! share each gets depends on the order they run in: pcap_analyzer, then, in ace3's trees, http,
//! files, dns and tls, a set's order there (`CATEGORY_ORDER`), then the decryption. Every one of them
//! adds what the same index says, so here each works out what those before it added rather than
//! read their results, and the shares come out the same on every run.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use ace_pycompat::pystr;
use ace_results::types::pcap::{Counts, DnsRow, PcapIndex, TlsRow};
use ace_results::{
    AlertPath, NewFile, NewObservable, ObservableKind, ObservableRef, Relationship,
    RelationshipKind,
};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::config::{EXCLUDED_FQDN_SUFFIXES, MAX_OBSERVABLES_PER_TYPE};
use crate::index::{
    CATEGORY_DNS, CATEGORY_FILES, CATEGORY_HOSTS, CATEGORY_HTTP, CATEGORY_TLS, split_url,
};
use crate::{alert_dir, item_list};

/// The order ace3's trees run the categories in.
pub const CATEGORY_ORDER: [&str; 4] = [CATEGORY_HTTP, CATEGORY_FILES, CATEGORY_DNS, CATEGORY_TLS];

/// The settings of the categories and the decryption: which categories the site runs, in the
/// order their shares of each type are worked out.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct PcapSettings {
    /// `http`, `files`, `dns` and `tls`, as ace3's trees run them. A site that turns a category
    /// off leaves it out, so the others get its share, as in ace3.
    pub categories: Vec<String>,
}

impl Default for PcapSettings {
    fn default() -> Self {
        PcapSettings {
            categories: CATEGORY_ORDER.iter().map(|c| (*c).to_owned()).collect(),
        }
    }
}

const NO_CRAWL: &str = "no_crawl";
const MAX_JA4_DESTINATIONS: usize = 3;

/// `PcapObservable`: one observable of the index, in its category.
#[derive(Debug, Clone, PartialEq)]
pub struct PcapObservable {
    pub category: &'static str,
    pub kind: ObservableKind,
    /// A file's sha256, so a file is the same observable whatever its path.
    pub value: String,
    /// A file's path, relative to the capture's directory.
    pub path: Option<String>,
    pub downloaded_from: Option<String>,
    /// A certificate ACE only observed on the wire, which x509_analyzer shouldn't crawl.
    pub no_crawl: bool,
    pub display_type: Option<String>,
    /// Epoch seconds.
    pub time: Option<f64>,
}

impl PcapObservable {
    fn new(category: &'static str, kind: ObservableKind, value: impl Into<String>) -> Self {
        PcapObservable {
            category,
            kind,
            value: value.into(),
            path: None,
            downloaded_from: None,
            no_crawl: false,
            display_type: None,
            time: None,
        }
    }

    pub fn key(&self) -> (ObservableKind, &str) {
        (self.kind, &self.value)
    }
}

/// `_is_interesting_ip`: an address, and not multicast, unspecified, link-local, loopback or
/// reserved, as Python's ipaddress says.
pub fn is_interesting_ip(value: &str) -> bool {
    if ace_pycompat::ipaddress::ip_address(value).is_err() {
        return false;
    }
    let bare = value.split('%').next().unwrap_or(value);
    let Ok(address) = bare.parse::<std::net::IpAddr>() else {
        return false;
    };
    let v4 = |a: std::net::Ipv4Addr| {
        let o = a.octets();
        !(a.is_multicast()
            || a.is_unspecified()
            || (o[0] == 169 && o[1] == 254)
            || o[0] == 127
            || o[0] >= 240)
    };
    match address {
        std::net::IpAddr::V4(a) => v4(a),
        std::net::IpAddr::V6(a) => {
            // Python 3.14 asks an IPv4-mapped address's IPv4 address
            if let Some(mapped) = a.to_ipv4_mapped() {
                return v4(mapped);
            }
            let s = a.segments();
            let multicast = s[0] >> 8 == 0xff;
            let link_local = s[0] & 0xffc0 == 0xfe80;
            !(multicast
                || a.is_unspecified()
                || link_local
                || a.is_loopback()
                || ipv6_reserved(s[0]))
        }
    }
}

/// IPv6Address.is_reserved: the IETF's reserved networks.
fn ipv6_reserved(first: u16) -> bool {
    const RESERVED: [(u16, u32); 15] = [
        (0x0000, 8),
        (0x0100, 8),
        (0x0200, 7),
        (0x0400, 6),
        (0x0800, 5),
        (0x1000, 4),
        (0x4000, 3),
        (0x6000, 3),
        (0x8000, 3),
        (0xa000, 3),
        (0xc000, 3),
        (0xe000, 4),
        (0xf000, 5),
        (0xf800, 6),
        (0xfe00, 9),
    ];
    RESERVED.iter().any(|&(network, bits)| {
        let mask = !0u16 << (16 - bits);
        first & mask == network
    })
}

/// `_is_interesting_mac`: the group bit is clear (no broadcast or multicast), and it isn't zeros.
pub fn is_interesting_mac(value: &str) -> bool {
    let first = value.split(':').next().unwrap_or_default();
    let Ok(octet) = u32::from_str_radix(pystr::strip(first), 16) else {
        return false;
    };
    octet & 1 == 0 && value != "00:00:00:00:00:00"
}

/// `_host_without_port`.
pub fn host_without_port(host: &str) -> &str {
    let host = pystr::strip(host);
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or_default();
    }
    if host.matches(':').count() == 1 {
        return host.split(':').next().unwrap_or_default();
    }
    host
}

/// `_host_observable`: an IP for an address worth one, an fqdn for any other name but the excluded.
fn host_observable(
    category: &'static str,
    host: &str,
    fqdn_display: Option<&str>,
    ip_display: Option<&str>,
    ip_time: Option<f64>,
) -> Option<PcapObservable> {
    let host = pystr::lower(pystr::rstrip_chars(host_without_port(host), ".")).into_owned();
    if host.is_empty() {
        return None;
    }
    if ace_pycompat::ipaddress::ip_address(&host).is_ok() {
        if !is_interesting_ip(&host) {
            return None;
        }
        let mut item = PcapObservable::new(category, ObservableKind::Ip, host);
        item.display_type = ip_display.map(str::to_owned);
        item.time = ip_time;
        return Some(item);
    }
    if EXCLUDED_FQDN_SUFFIXES.iter().any(|s| host.ends_with(s)) {
        return None;
    }
    let mut item = PcapObservable::new(category, ObservableKind::Fqdn, host);
    item.display_type = fqdn_display.map(str::to_owned);
    Some(item)
}

/// `ja4_display_types`: for each JA4, where its sessions went.
fn ja4_display_types(sessions: &[TlsRow]) -> HashMap<String, String> {
    let mut destinations: Vec<(String, Vec<String>)> = Vec::new();
    for session in sessions {
        let Some(ja4) = session.ja4.clone().flatten().filter(|j| !j.is_empty()) else {
            continue;
        };
        let sni = session.sni.clone().flatten().filter(|s| !s.is_empty());
        let server = session.server.clone().flatten().unwrap_or_default();
        let target =
            sni.or_else(|| Some(host_without_port(&server).to_owned()).filter(|s| !s.is_empty()));
        let i = match destinations.iter().position(|(j, _)| *j == ja4) {
            Some(i) => i,
            None => {
                destinations.push((ja4, Vec::new()));
                destinations.len() - 1
            }
        };
        let targets = &mut destinations[i].1;
        if let Some(target) = target
            && !targets.contains(&target)
        {
            targets.push(target);
        }
    }
    // JA4 describes the client that sent the hello, not the server: one per client application is
    // normal
    destinations
        .into_iter()
        .map(|(ja4, targets)| {
            let label = if targets.is_empty() {
                "JA4 client fingerprint (TLS ClientHello)".to_owned()
            } else {
                format!(
                    "JA4 client fingerprint (TLS ClientHello), seen to {}",
                    item_list(&targets, MAX_JA4_DESTINATIONS)
                )
            };
            (ja4, label)
        })
        .collect()
}

/// `_dns_display_type`: how the name was seen, the most direct way first.
fn dns_display_type(row: &DnsRow) -> &'static str {
    if row.queries > 0 || row.responses > 0 {
        return "DNS Query Name";
    }
    if row.seen_as.iter().any(|r| r == "cname") {
        return "DNS CNAME Target";
    }
    if row.seen_as.iter().any(|r| r == "zone") {
        return "DNS Zone (SOA/NS)";
    }
    "DNS Record Name"
}

/// `collect_observables`: every observable the index holds, each in the category whose result adds
/// it, the first of each in a category kept, as it carries the most specific display type.
pub fn collect_observables(index: &PcapIndex) -> Vec<PcapObservable> {
    let mut result: Vec<PcapObservable> = Vec::new();
    let mut seen: BTreeSet<(&'static str, ObservableKind, String)> = BTreeSet::new();
    let mut add = |item: Option<PcapObservable>| {
        if let Some(item) = item
            && seen.insert((item.category, item.kind, item.value.clone()))
        {
            result.push(item);
        }
    };

    let statistics = index.statistics.clone().unwrap_or_default();
    for row in statistics.ip.unwrap_or_default() {
        if is_interesting_ip(&row.address) {
            add(Some(PcapObservable::new(
                CATEGORY_HOSTS,
                ObservableKind::Ip,
                row.address,
            )));
        }
    }
    for row in statistics.mac.unwrap_or_default() {
        let mac = ace_sdk::layer2::normalize_mac_address(&row.address);
        if let Some(mac) = mac
            && is_interesting_mac(&row.address)
        {
            add(Some(PcapObservable::new(
                CATEGORY_HOSTS,
                ObservableKind::MacAddress,
                mac,
            )));
        }
    }
    for row in &index.hostnames {
        add(Some(PcapObservable::new(
            CATEGORY_HOSTS,
            ObservableKind::Hostname,
            &row.name,
        )));
    }

    for row in &index.dns {
        add(host_observable(
            CATEGORY_DNS,
            &row.name,
            Some(dns_display_type(row)),
            None,
            None,
        ));
    }
    // one observable per answer IP, at the first time any response returned it
    let mut first_answered: HashMap<&str, f64> = HashMap::new();
    for row in &index.dns {
        for (answer, &seen_at) in row.answer_times.iter().flatten() {
            if first_answered
                .get(answer.as_str())
                .is_none_or(|t| seen_at < *t)
            {
                first_answered.insert(answer, seen_at);
            }
        }
    }
    for row in &index.dns {
        for answer in &row.answers {
            add(host_observable(
                CATEGORY_DNS,
                answer,
                None,
                Some("DNS Answer IP"),
                first_answered.get(answer.as_str()).copied(),
            ));
        }
    }

    let ja4_labels = ja4_display_types(&index.tls);
    // a name DNS also saw keeps its DNS label, so the label never depends on which category ran
    // first
    let dns_names: BTreeSet<&str> = index.dns.iter().map(|r| r.name.as_str()).collect();
    for row in &index.tls {
        if let Some(sni) = row.sni.clone().flatten().filter(|s| !s.is_empty()) {
            let seen = dns_names.contains(pystr::lower(pystr::rstrip_chars(&sni, ".")).as_ref());
            let label = (!seen).then_some("TLS SNI");
            add(host_observable(CATEGORY_TLS, &sni, label, None, None));
        }
        if let Some(ja4) = row.ja4.clone().flatten().filter(|j| !j.is_empty()) {
            let mut item = PcapObservable::new(CATEGORY_TLS, ObservableKind::Ja4, &ja4);
            item.display_type = ja4_labels.get(&ja4).cloned();
            add(Some(item));
        }
    }
    for row in &index.certificates {
        if let Some(path) = row.path.clone().filter(|p| !p.is_empty()) {
            let mut item = PcapObservable::new(CATEGORY_TLS, ObservableKind::File, &row.sha256);
            item.path = Some(path);
            item.no_crawl = true;
            add(Some(item));
        }
    }

    for row in &index.http {
        if let Some(url) = row.url.as_deref().filter(|u| !u.is_empty())
            && split_url(url).is_some_and(|p| p.scheme == "http" || p.scheme == "https")
        {
            add(Some(PcapObservable::new(
                CATEGORY_HTTP,
                ObservableKind::Url,
                url,
            )));
        }
        if let Some(host) = row.host.as_deref().filter(|h| !h.is_empty()) {
            add(host_observable(CATEGORY_HTTP, host, None, None, None));
        }
        if let Some(agent) = row.user_agent.as_deref().filter(|a| !a.is_empty()) {
            add(Some(PcapObservable::new(
                CATEGORY_HTTP,
                ObservableKind::UserAgent,
                agent,
            )));
        }
    }

    for row in &index.objects {
        if let Some(path) = row.path.clone().filter(|p| !p.is_empty()) {
            let mut item = PcapObservable::new(CATEGORY_FILES, ObservableKind::File, &row.sha256);
            item.path = Some(path);
            item.downloaded_from = row.url.clone().flatten();
            add(Some(item));
        }
    }
    result
}

/// What one pcap result added: its observables, by type and value (ace3's `analysis.observables`,
/// for the next result's counts), and the records it adds.
#[derive(Debug, Clone, Default)]
pub struct Node {
    pub observables: Vec<(ObservableKind, String)>,
    pub added: Counts,
    pub omitted: Counts,
    pub new_observables: Vec<NewObservable>,
    pub new_files: Vec<NewFile>,
}

impl Node {
    fn hold(&mut self, kind: ObservableKind, value: &str) {
        if !self
            .observables
            .iter()
            .any(|(k, v)| *k == kind && v == value)
        {
            self.observables.push((kind, value.to_owned()));
        }
    }
}

/// The capture the observables come from: its observable, and its directory in the alert, which
/// carved files' paths are relative to.
pub struct CaptureFile<'a> {
    pub sha256: &'a str,
    pub path: &'a str,
}

/// `add_pcap_observables`: `items` added to a new result, at most `MAX_OBSERVABLES_PER_TYPE` of each
/// type for the whole capture, counting what the `earlier` results hold, and keeping room for
/// `reserved`, which another result adds later. A payload file goes before a certificate.
pub fn add(
    capture: &CaptureFile<'_>,
    items: &[PcapObservable],
    earlier: &[&Node],
    reserved: &[PcapObservable],
) -> Node {
    let mut node = Node::default();
    let mut present: BTreeSet<(ObservableKind, String)> = BTreeSet::new();
    let mut per_type: BTreeMap<String, u64> = BTreeMap::new();
    let mut in_capture: BTreeSet<(ObservableKind, String)> = BTreeSet::new();
    for other in earlier {
        for (kind, value) in &other.observables {
            *per_type.entry(kind.as_str().to_owned()).or_default() += 1;
            in_capture.insert((*kind, value.clone()));
        }
    }
    for item in reserved {
        if !in_capture.contains(&(item.kind, item.value.clone())) {
            *per_type.entry(item.kind.as_str().to_owned()).or_default() += 1;
        }
    }
    let mut ordered: Vec<&PcapObservable> = items.iter().collect();
    ordered.sort_by_key(|item| item.no_crawl);
    let capture_ref = ObservableRef::new(ObservableKind::File, capture.sha256);
    for item in ordered {
        let kind_name = item.kind.as_str().to_owned();
        if present.contains(&(item.kind, item.value.clone())) {
            continue;
        }
        if per_type.get(&kind_name).copied().unwrap_or(0) >= MAX_OBSERVABLES_PER_TYPE {
            *node.omitted.entry(kind_name).or_default() += 1;
            continue;
        }
        let added = if item.kind == ObservableKind::File {
            file(capture, item, &capture_ref, &mut node)
        } else {
            observable(item, &mut node)
        };
        if !added {
            // a value ace3's observable type refuses
            *node.omitted.entry(kind_name).or_default() += 1;
            continue;
        }
        present.insert((item.kind, item.value.clone()));
        *per_type.entry(kind_name.clone()).or_default() += 1;
        *node.added.entry(kind_name).or_default() += 1;
    }
    node
}

/// A file observable: the carved file, extracted from the capture, maybe downloaded from a URL.
fn file(
    capture: &CaptureFile<'_>,
    item: &PcapObservable,
    capture_ref: &ObservableRef,
    node: &mut Node,
) -> bool {
    let (Some(path), Ok(sha256)) = (&item.path, item.value.parse()) else {
        return false;
    };
    let Ok(path) = AlertPath::new(format!("{}{path}", alert_dir(capture.path))) else {
        return false;
    };
    // its size is the bucket's: the result that carved it stored it
    let mut new_file = NewFile::new(path, sha256, 0);
    new_file.relationships.push(Relationship::new(
        RelationshipKind::ExtractedFrom,
        capture_ref.clone(),
    ));
    if item.no_crawl {
        new_file.directives.push(NO_CRAWL.to_owned());
    }
    if let Some(url) = &item.downloaded_from
        && let Some(observable) = ace_mod_values::observable::new(ObservableKind::Url, url)
    {
        new_file.relationships.push(Relationship::new(
            RelationshipKind::DownloadedFrom,
            ObservableRef::new(ObservableKind::Url, observable.value.clone()),
        ));
        node.hold(ObservableKind::Url, &observable.value);
        if !node
            .new_observables
            .iter()
            .any(|o| o.kind == ObservableKind::Url && o.value == observable.value)
        {
            node.new_observables.push(observable);
        }
    }
    node.hold(ObservableKind::File, &item.value);
    node.new_files.push(new_file);
    true
}

/// Any other observable, as ace3's type takes its value.
fn observable(item: &PcapObservable, node: &mut Node) -> bool {
    let Some(mut observable) = ace_mod_values::observable::new(item.kind, &item.value) else {
        return false;
    };
    observable.time = item.time.and_then(from_timestamp);
    // an observable has one display type wherever it appears: never replace another module's
    observable.display_type = item.display_type.clone();
    node.hold(item.kind, &observable.value);
    if let Some(existing) = node
        .new_observables
        .iter_mut()
        .find(|o| o.kind == observable.kind && o.value == observable.value)
    {
        existing.time = existing.time.or(observable.time);
    } else {
        node.new_observables.push(observable);
    }
    true
}

/// `datetime.fromtimestamp(t, timezone.utc)`: to the microsecond, rounding half to even.
pub fn from_timestamp(t: f64) -> Option<DateTime<Utc>> {
    if !t.is_finite() {
        return None;
    }
    let whole = t.trunc();
    let frac = t - whole;
    let mut us = (frac * 1e6).round_ties_even() as i64;
    let mut seconds = whole as i64;
    if us >= 1_000_000 {
        seconds += 1;
        us -= 1_000_000;
    } else if us < 0 {
        seconds -= 1;
        us += 1_000_000;
    }
    DateTime::from_timestamp(seconds, (us * 1000) as u32)
}

/// The categories' results in ace3's order, each counting those before it: the hosts' result is
/// pcap_analyzer's.
pub struct Shares {
    pub hosts: Node,
    pub categories: Vec<(&'static str, Node)>,
}

/// Works out what pcap_analyzer and each category in `order` add from the plaintext index, then
/// `last`, when `order` doesn't have it.
pub fn shares(
    capture: &CaptureFile<'_>,
    index: &PcapIndex,
    order: &[String],
    last: Option<&'static str>,
) -> Shares {
    let everything = collect_observables(index);
    let in_category = |category: &str| -> Vec<PcapObservable> {
        everything
            .iter()
            .filter(|o| o.category == category)
            .cloned()
            .collect()
    };
    let hosts = add(capture, &in_category(CATEGORY_HOSTS), &[], &[]);
    let files = in_category(CATEGORY_FILES);
    let mut categories: Vec<(&'static str, Node)> = Vec::new();
    // the settings' categories, each once, in their order
    let mut run: Vec<&'static str> = Vec::new();
    for name in order {
        if let Some(known) = CATEGORY_ORDER.iter().find(|c| **c == name.as_str())
            && !run.contains(known)
        {
            run.push(known);
        }
    }
    if let Some(last) = last
        && !run.contains(&last)
    {
        run.push(last);
    }
    for category in run {
        let items = in_category(category);
        // nothing in the capture for this category: no result
        if items.is_empty() && category_rows(index, category) == 0 {
            categories.push((category, Node::default()));
            continue;
        }
        let earlier: Vec<&Node> = std::iter::once(&hosts)
            .chain(categories.iter().map(|(_, n)| n))
            .collect();
        // the files result may come after this one: its payload files keep their room
        let reserved: &[PcapObservable] = if category == CATEGORY_FILES {
            &[]
        } else {
            &files
        };
        let node = add(capture, &items, &earlier, reserved);
        categories.push((category, node));
    }
    Shares { hosts, categories }
}

impl Shares {
    pub fn category(&self, category: &str) -> &Node {
        &self
            .categories
            .iter()
            .find(|(c, _)| *c == category)
            .expect("a category")
            .1
    }

    /// Every result's, in order.
    pub fn all(&self) -> Vec<&Node> {
        std::iter::once(&self.hosts)
            .chain(self.categories.iter().map(|(_, n)| n))
            .collect()
    }
}

/// How many rows the index has for a category.
pub fn category_rows(index: &PcapIndex, category: &str) -> usize {
    match category {
        CATEGORY_DNS => index.dns.len(),
        CATEGORY_TLS => index.tls.len(),
        CATEGORY_HTTP => index.http.len(),
        _ => index.objects.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_interesting_as_pythons_ipaddress_says() {
        for (address, interesting) in [
            ("10.20.30.40", true),
            ("0.0.0.0", false),
            ("255.255.255.255", false),
            ("224.0.0.251", false),
            ("169.254.1.1", false),
            ("127.0.0.1", false),
            ("2001:db8::1", true),
            ("::1", false),
            ("fe80::1%eth0", false),
            ("ff02::1:2", false),
            ("::ffff:10.0.0.1", true),
            ("::ffff:127.0.0.1", false),
            ("not an address", false),
        ] {
            assert_eq!(is_interesting_ip(address), interesting, "{address}");
        }
        assert!(is_interesting_mac("02:00:00:aa:00:01"));
        assert!(!is_interesting_mac("ff:ff:ff:ff:ff:ff"));
        assert!(!is_interesting_mac("33:33:00:01:00:02"));
        assert!(!is_interesting_mac("00:00:00:00:00:00"));
    }

    #[test]
    fn hosts_lose_their_ports() {
        assert_eq!(host_without_port("[2001:db8::1]:80"), "2001:db8::1");
        assert_eq!(host_without_port("example.com:8080"), "example.com");
        assert_eq!(host_without_port("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn times_round_to_the_microsecond_as_python_does() {
        let t = from_timestamp(1767225603.0000005).unwrap();
        assert_eq!(t.timestamp_subsec_micros(), 0);
        let t = from_timestamp(1792604746.451967).unwrap();
        assert_eq!(t.timestamp_subsec_micros(), 451967);
    }
}
