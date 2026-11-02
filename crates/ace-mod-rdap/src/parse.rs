//! What ace3 reads from an RDAP response, which whoisit parses for it (`whoisit/parser.py`):
//! names, contacts, dates and, for an IP address, its network.
//!
//! icann-rdap-common reads the response's structure. vCards are read the way whoisit reads them,
//! because whoisit decides which of a contact's names and email addresses ace3 keeps.

use std::net::IpAddr;

use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeDelta, Utc};
use icann_rdap_common::response::{Link, ObjectCommonFields, RdapResponse};
use ipnet::IpNet;
use serde_json::Value;

/// A date as an RDAP server wrote it: with its offset, or without one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdapDate {
    Aware(DateTime<FixedOffset>),
    Naive(NaiveDateTime),
}

impl RdapDate {
    /// Reads an `eventDate`. whoisit uses dateutil, which reads more forms than these; RDAP
    /// servers write RFC 3339.
    pub fn parse(text: &str) -> Option<RdapDate> {
        let text = text.trim();
        if let Ok(date) = DateTime::parse_from_rfc3339(text) {
            return Some(RdapDate::Aware(date));
        }
        for format in ["%Y-%m-%dT%H:%M:%S%.f%z", "%Y-%m-%dT%H:%M:%S%.f%#z"] {
            if let Ok(date) = DateTime::parse_from_str(text, format) {
                return Some(RdapDate::Aware(date));
            }
        }
        for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
            if let Ok(date) = NaiveDateTime::parse_from_str(text, format) {
                return Some(RdapDate::Naive(date));
            }
        }
        None
    }

    /// Python's `isoformat(" ")`: microseconds only when there are any, and the offset when the
    /// date has one.
    pub fn isoformat(&self) -> String {
        match self {
            RdapDate::Aware(date) => isoformat(&date.naive_local(), Some(date.offset())),
            RdapDate::Naive(date) => isoformat(date, None),
        }
    }

    fn utc(&self) -> DateTime<Utc> {
        match self {
            RdapDate::Aware(date) => date.with_timezone(&Utc),
            RdapDate::Naive(date) => date.and_utc(),
        }
    }

    /// `_age_in_days_as_string`: whole days from this date to `now`, 0 when the date is later.
    pub fn age_in_days(&self, now: DateTime<Utc>) -> String {
        let delta: TimeDelta = now - self.utc();
        // timedelta.days rounds down
        let days = delta.num_seconds().div_euclid(86_400);
        days.max(0).to_string()
    }
}

fn isoformat(date: &NaiveDateTime, offset: Option<&FixedOffset>) -> String {
    let mut text = date.format("%Y-%m-%d %H:%M:%S").to_string();
    let micros = date.and_utc().timestamp_subsec_micros();
    if micros != 0 {
        text.push_str(&format!(".{micros:06}"));
    }
    if let Some(offset) = offset {
        let seconds = offset.local_minus_utc();
        let sign = if seconds < 0 { '-' } else { '+' };
        let seconds = seconds.abs();
        text.push_str(&format!(
            "{sign}{:02}:{:02}",
            seconds / 3600,
            seconds / 60 % 60
        ));
    }
    text
}

/// `isoformat(" ")` of the time a lookup ran.
pub fn isoformat_utc(now: DateTime<Utc>) -> String {
    isoformat(
        &now.naive_utc(),
        Some(&FixedOffset::east_opt(0).expect("zero offset")),
    )
}

/// What the module keeps from a response.
#[derive(Debug, Default, PartialEq)]
pub struct Parsed {
    /// `name`: the domain's `ldhName`, or the network's `name`.
    pub name: String,
    /// The last `self` link.
    pub url: String,
    pub registrar: Option<String>,
    pub nameservers: Vec<String>,
    pub emails: Vec<String>,
    pub registration: Option<RdapDate>,
    pub last_changed: Option<RdapDate>,
    pub expiration: Option<RdapDate>,
    pub network: Option<String>,
    pub country: String,
    pub ip_version: Option<u8>,
    pub assignment_type: String,
}

/// whoisit's `clean`.
fn clean(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(text)) => text.trim().to_owned(),
        Some(other) => other.to_string().trim().to_owned(),
    }
}

/// The name and email addresses whoisit's `parse_vcard` finds in a jCard: the name is the last
/// `fn` or `org`, and the emails keep their order without duplicates.
fn vcard(vcard: &[Value]) -> (Option<String>, Vec<String>) {
    let mut name = None;
    let mut emails: Vec<String> = Vec::new();
    let [Value::String(kind), Value::Array(fields)] = vcard else {
        return (None, emails);
    };
    if kind != "vcard" {
        return (None, emails);
    }
    for field in fields {
        let Some([entry_field, _, entry_type, entry_label]) = field
            .as_array()
            .and_then(|f| <&[Value; 4]>::try_from(f.as_slice()).ok())
        else {
            continue;
        };
        let entry_field = entry_field.as_str().unwrap_or_default();
        if entry_field == "email" {
            let mut email = clean(Some(entry_label));
            if email.to_lowercase().starts_with("mailto:") {
                email = email[7..].to_owned();
            }
            if !email.is_empty() && !emails.contains(&email) {
                emails.push(email);
            }
        } else if entry_type.as_str() != Some("text") {
            continue;
        } else if entry_field == "fn" || entry_field == "org" {
            name = Some(clean(Some(entry_label)));
        }
    }
    (name.filter(|n| !n.is_empty()), emails)
}

/// Every entity, depth first, as whoisit's `extract_entities` walks them. They are read from
/// the response's JSON, because icann-rdap-common keeps an entity's jCard to itself and whoisit
/// reads the jCard's fields in order.
fn walk_entities<'a>(entities: &'a Value, out: &mut Vec<&'a Value>) {
    for entity in entities.as_array().into_iter().flatten() {
        if !entity.is_object() {
            continue;
        }
        out.push(entity);
        walk_entities(&entity["entities"], out);
    }
}

/// The last `self` link, as whoisit keeps the last one it sees.
fn self_link(links: &[Link]) -> String {
    links
        .iter()
        .rev()
        .filter(|link| {
            link.rel()
                .is_some_and(|rel| rel.trim().eq_ignore_ascii_case("self"))
        })
        .filter_map(|link| link.href())
        .map(|href| href.trim().to_owned())
        .next()
        .unwrap_or_default()
}

/// whoisit's `extract_dates`: the last event of each action wins.
fn dates(raw: &Value, parsed: &mut Parsed) {
    for event in raw["events"].as_array().into_iter().flatten() {
        let action = clean(event.get("eventAction")).to_lowercase();
        let Some(date) = event["eventDate"].as_str().and_then(RdapDate::parse) else {
            continue;
        };
        match action.as_str() {
            "last changed" => parsed.last_changed = Some(date),
            "registration" => parsed.registration = Some(date),
            "expiration" => parsed.expiration = Some(date),
            _ => {}
        }
    }
}

/// Reads a domain or network response. `query` is the IP address asked about, for picking the
/// network that holds it.
pub fn parse(raw: &Value, query: Option<IpAddr>) -> Result<Parsed, String> {
    let response = RdapResponse::try_from(raw.clone()).map_err(|e| e.to_string())?;
    let mut parsed = Parsed::default();
    dates(raw, &mut parsed);
    let links = match &response {
        RdapResponse::Domain(domain) => {
            parsed.name = clean(raw.get("ldhName"));
            parsed.nameservers = domain
                .nameservers()
                .iter()
                .filter(|ns| ns.object_common.object_class_name == "nameserver")
                .filter_map(|ns| ns.ldh_name().map(|n| n.trim().to_owned()))
                .filter(|n| !n.is_empty())
                .collect();
            domain.links()
        }
        RdapResponse::Network(network) => {
            parsed.name = clean(raw.get("name"));
            parsed.country = clean(raw.get("country"));
            parsed.assignment_type = clean(raw.get("type")).to_lowercase();
            parsed.ip_version = match clean(raw.get("ipVersion")).as_str() {
                "v4" => Some(4),
                "v6" => Some(6),
                _ => None,
            };
            parsed.network = network_of(raw, query);
            network.links()
        }
        other => return Err(format!("unexpected RDAP response type {other}")),
    };
    parsed.url = self_link(links);

    let mut all = Vec::new();
    walk_entities(&raw["entities"], &mut all);
    for entity in all {
        let (name, emails) = entity["vcardArray"]
            .as_array()
            .map(|card| vcard(card))
            .unwrap_or_default();
        let roles: Vec<String> = entity["roles"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| r.as_str().map(str::to_lowercase))
            .collect();
        if roles.is_empty() {
            // whoisit files an entity under each of its roles; one with none is dropped
            continue;
        }
        if parsed.registrar.is_none() && roles.iter().any(|r| r == "registrar") {
            parsed.registrar = name;
        }
        if let Some(email) = emails.into_iter().next()
            && !parsed.emails.contains(&email)
        {
            parsed.emails.push(email);
        }
    }
    Ok(parsed)
}

/// whoisit's `extract_network`: the `cidr0_cidrs` network that holds the query (or the first),
/// else the first network of the start and end addresses.
fn network_of(raw: &Value, query: Option<IpAddr>) -> Option<String> {
    if let Some(cidrs) = raw["cidr0_cidrs"].as_array() {
        for cidr in cidrs {
            let length = cidr["length"].as_u64().map(|l| l.to_string()).or_else(|| {
                cidr["length"]
                    .as_str()
                    .filter(|l| !l.is_empty())
                    .map(str::to_owned)
            })?;
            let prefix = cidr["v4prefix"]
                .as_str()
                .filter(|p| !p.is_empty())
                .or_else(|| cidr["v6prefix"].as_str().filter(|p| !p.is_empty()))?;
            let net: IpNet = format!("{prefix}/{length}").parse().ok()?;
            match query {
                Some(ip) if ip.is_ipv4() == net.addr().is_ipv4() => {
                    if net.contains(&ip) {
                        return Some(net.to_string());
                    }
                }
                _ => return Some(net.to_string()),
            }
        }
        return None;
    }
    let start: IpAddr = raw["startAddress"].as_str()?.trim().parse().ok()?;
    let end: IpAddr = raw["endAddress"].as_str()?.trim().parse().ok()?;
    let first = match (start, end) {
        (IpAddr::V4(start), IpAddr::V4(end)) => {
            ipnet::Ipv4Subnets::new(start, end, 0).next().map(IpNet::V4)
        }
        (IpAddr::V6(start), IpAddr::V6(end)) => {
            ipnet::Ipv6Subnets::new(start, end, 0).next().map(IpNet::V6)
        }
        _ => None,
    };
    first.map(|net| net.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dates_print_like_isoformat() {
        let date = RdapDate::parse("2023-12-28T17:24:33-05:00").expect("parses");
        assert_eq!(date.isoformat(), "2023-12-28 17:24:33-05:00");
        let date = RdapDate::parse("1995-08-14T04:00:00Z").expect("parses");
        assert_eq!(date.isoformat(), "1995-08-14 04:00:00+00:00");
        let now = DateTime::parse_from_rfc3339("2026-11-02T15:28:28.397872Z")
            .expect("parses")
            .with_timezone(&Utc);
        assert_eq!(isoformat_utc(now), "2026-11-02 15:28:28.397872+00:00");
        assert_eq!(date.age_in_days(now), "11403");
        let future = RdapDate::parse("2030-01-01T00:00:00Z").expect("parses");
        assert_eq!(future.age_in_days(now), "0");
    }

    #[test]
    fn vcards_keep_the_last_name_and_the_first_email() {
        let card = json!([
            "vcard",
            [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "Person"],
                ["org", {}, "text", "Company"],
                ["email", {}, "text", "mailto:first@example.com"],
                ["email", {}, "text", "second@example.com"],
            ]
        ]);
        let (name, emails) = vcard(card.as_array().expect("an array"));
        assert_eq!(name.as_deref(), Some("Company"));
        assert_eq!(emails, ["first@example.com", "second@example.com"]);
    }

    #[test]
    fn a_network_without_cidr0_takes_the_first_of_its_range() {
        let raw = json!({"startAddress": "10.0.0.0", "endAddress": "10.0.2.255"});
        assert_eq!(network_of(&raw, None).as_deref(), Some("10.0.0.0/23"));
    }
}
