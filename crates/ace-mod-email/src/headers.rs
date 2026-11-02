//! The header facts ace3's `rfc822.py` reads: the first external hop, DKIM signing domains, the
//! sender's tenant, authentication verdicts and the time a message was received.

use std::net::IpAddr;
use std::sync::LazyLock;

use chrono::{DateTime, FixedOffset, NaiveDate, TimeDelta, TimeZone, Utc};
use regex::Regex;

use crate::py::{Headers, decode_rfc2822, py_strip};
use crate::settings::ProviderHeaders;

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("valid regex")
}

static RECEIVED_FROM: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bfrom\s+(\S+)"));
static RECEIVED_BY: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bby\s+(\S+)"));
static RECEIVED_HELO: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\bhelo\s*[=\s]\s*([^\s()\[\],;]+)"));
static RECEIVED_GROUP: LazyLock<Regex> = LazyLock::new(|| re(r"[(\[]([^)\]]*)[)\]]"));
static RECEIVED_PARENS: LazyLock<Regex> = LazyLock::new(|| re(r"\(([^)]*)\)"));
static HOSTNAME: LazyLock<Regex> = LazyLock::new(|| re(r"\b([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)\b"));
static DKIM_SIGNING_DOMAIN: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)(?:^|;)\s*d\s*=\s*([^;\s]+)"));
static IP_TOKEN: LazyLock<Regex> = LazyLock::new(|| re(r"\[?([0-9a-fA-F:.]+)\]?"));
static AUTH_SPF: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bspf=(\w+)"));
static AUTH_DKIM: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bdkim=(\w+)"));
static AUTH_DMARC: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bdmarc=(\w+)"));
static AUTH_COMPAUTH: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bcompauth=(\w+)"));
static AUTH_COMPAUTH_REASON: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\breason=(\w+)"));
/// `_PATTERN_RECEIVED_IPADDR`, used with `match`, so anchored at the start.
static RECEIVED_IPADDR: LazyLock<Regex> = LazyLock::new(|| re(r"^from\s\S+\s\(([^)]+)\)\s"));
/// `RE_EMAIL_RECEIVED_DATE`, `;\s?(.+)$` without MULTILINE: `.` stops at a line break, and `$`
/// matches at the end or before a final line break.
static RECEIVED_DATE: LazyLock<Regex> = LazyLock::new(|| re(r";\s?([^\n]+)\n?\z"));

/// Python's `str(ipaddress.ip_address(text))`, or None when it isn't an address.
pub fn parse_ip(text: &str) -> Option<String> {
    // Python accepts an IPv6 scope id, which std doesn't; ace3 never sees one in a header
    text.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

/// `normalize_ip_header_value`: the address in a header such as `X-Originating-IP: [10.0.0.1]`.
pub fn normalize_ip_header_value(value: &str) -> Option<String> {
    let candidate = py_strip(py_strip(value).trim_matches(['[', ']']));
    parse_ip(candidate)
}

/// `extract_first_hop_ip`: the address in a first-hop header, bare or inside a structured value
/// such as `TenantId=<guid>;Ip=[<ip>];Helo=[<host>]`.
pub fn extract_first_hop_ip(value: &str) -> Option<String> {
    if let Some(ip) = normalize_ip_header_value(value) {
        return Some(ip);
    }
    IP_TOKEN
        .captures_iter(value)
        .find_map(|caps| parse_ip(&caps[1]))
}

/// `_received_from_clause`: the part of a Received header between `from` and `by`.
fn received_from_clause(received: &str) -> &str {
    let Some(m) = RECEIVED_FROM.find(received) else {
        return "";
    };
    let tail = &received[m.end()..];
    match RECEIVED_BY.find(tail) {
        Some(by) => &tail[..by.start()],
        None => tail,
    }
}

fn looks_like_ip(value: &str) -> bool {
    !value.is_empty() && parse_ip(value.trim_matches(['[', ']'])).is_some()
}

/// `_received_rdns_host`: the reverse-DNS host in the parentheses of a `from` clause.
fn received_rdns_host(from_clause: &str) -> Option<String> {
    let parens = RECEIVED_PARENS.captures(from_clause)?;
    HOSTNAME
        .captures_iter(&parens[1])
        .map(|caps| caps[1].to_owned())
        .find(|host| !host.eq_ignore_ascii_case("unknown") && !looks_like_ip(host))
        .map(|host| host.to_lowercase())
}

/// `_extract_hop_ip`: the sending address in the `from` clause of a Received header.
fn extract_hop_ip(received: &str) -> Option<String> {
    for caps in RECEIVED_GROUP.captures_iter(received_from_clause(received)) {
        let group = caps[1].replace(['[', ']'], " ");
        for token in group.split_whitespace() {
            if let Some(ip) = parse_ip(token.trim_matches(['.', ',', ';'])) {
                return Some(ip);
            }
        }
    }
    None
}

/// `is_subdomain` in `saq/util/networking.py`: `src` is `dst` or a subdomain of it.
pub fn is_subdomain(src: &str, dst: &str) -> bool {
    let src = src.to_lowercase();
    let dst = dst.to_lowercase();
    let src: Vec<&str> = src.split('.').rev().collect();
    let dst: Vec<&str> = dst.split('.').rev().collect();
    dst.iter()
        .enumerate()
        .all(|(i, part)| src.get(i).is_some_and(|s| s == part))
}

/// The first external hop: (ip, helo, host).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FirstHop {
    pub ip: Option<String>,
    pub helo: Option<String>,
    pub from: Option<String>,
}

/// `resolve_first_hop`: the provider's first-hop header if there is one, otherwise the earliest
/// Received hop that one of the organization's own hosts accepted from a public address.
pub fn resolve_first_hop(
    headers: &Headers,
    ip_headers: &[String],
    local_domains: &[String],
) -> FirstHop {
    let received: Vec<String> = headers
        .get_all("received")
        .iter()
        .map(decode_rfc2822)
        .collect();

    let mut hop_ip = None;
    for header in ip_headers {
        if let Some(value) = headers.get(header) {
            hop_ip = extract_first_hop_ip(&decode_rfc2822(&value));
            if hop_ip.is_some() {
                break;
            }
        }
    }

    let mut hop_header: Option<&String> = None;
    if let Some(ip) = &hop_ip {
        hop_header = received
            .iter()
            .find(|r| extract_hop_ip(r).as_ref() == Some(ip));
    } else {
        // earliest first, so the first local receipt is the perimeter
        for header in received.iter().rev() {
            let Some(by) = RECEIVED_BY.captures(header) else {
                continue;
            };
            let by_host = by[1].trim_matches(['.', ',', ';']);
            if !local_domains.iter().any(|d| is_subdomain(by_host, d)) {
                continue;
            }
            let candidate = extract_hop_ip(header);
            if let Some(ip) = &candidate
                && ip.parse::<IpAddr>().is_ok_and(ace_sdk::ip::is_private)
            {
                // an internal relay handing off to another internal host
                continue;
            }
            hop_header = Some(header);
            hop_ip = candidate;
            break;
        }
    }

    let Some(hop_header) = hop_header else {
        return FirstHop {
            ip: hop_ip,
            ..FirstHop::default()
        };
    };

    let from_clause = received_from_clause(hop_header);
    let inline_helo = RECEIVED_HELO
        .captures(from_clause)
        .map(|caps| caps[1].trim_matches(['[', ']']).to_lowercase());
    let from_token = RECEIVED_FROM.captures(hop_header).map(|caps| {
        caps[1]
            .trim_matches(['.', ',', ';'])
            .trim_matches(['[', ']'])
            .to_lowercase()
    });

    let (helo, from) = match inline_helo {
        Some(helo) => {
            let from = from_token.filter(|token| !looks_like_ip(token));
            (Some(helo), from)
        }
        None => (from_token, received_rdns_host(from_clause)),
    };
    FirstHop {
        ip: hop_ip,
        helo,
        from,
    }
}

/// `get_dkim_signing_domains`: the `d=` domain of every DKIM-Signature, without duplicates.
pub fn dkim_signing_domains(headers: &Headers) -> Vec<String> {
    let mut domains: Vec<String> = Vec::new();
    for header in headers.get_all("dkim-signature") {
        let value = decode_rfc2822(&header);
        let Some(caps) = DKIM_SIGNING_DOMAIN.captures(&value) else {
            continue;
        };
        let domain = caps[1].trim_matches('.').to_lowercase();
        if !domain.is_empty() && !domains.contains(&domain) {
            domains.push(domain);
        }
    }
    domains
}

/// `uuid.UUID(value)` as a canonical string, or None.
fn parse_uuid(value: &str) -> Option<String> {
    let hex = value
        .replace("urn:", "")
        .replace("uuid:", "")
        .trim_matches(['{', '}'])
        .replace('-', "");
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let hex = hex.to_lowercase();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

/// `get_sender_tenant_id`: the sending organization's tenant GUID.
pub fn sender_tenant_id(headers: &Headers, tenant_headers: &[String]) -> Option<String> {
    tenant_headers.iter().find_map(|header| {
        let value = headers.decoded(header)?;
        parse_uuid(py_strip(&value))
    })
}

/// `_first_present_header`: the decoded value of the first of `names` the message has.
pub fn first_present_header(headers: &Headers, names: &[String]) -> Option<String> {
    names
        .iter()
        .find_map(|name| headers.decoded(name).map(|v| py_strip(&v).to_owned()))
}

/// The verdicts `parse_email_authentication` returns.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Authentication {
    pub spf_result: Option<String>,
    pub dkim_result: Option<String>,
    pub dmarc_result: Option<String>,
    pub compauth_result: Option<String>,
    pub compauth_reason: Option<String>,
    pub is_anonymous_direct_send: bool,
    pub internal_org_sender: bool,
    pub message_directionality: Option<String>,
}

/// `parse_email_authentication`.
pub fn parse_authentication(headers: &Headers, provider: &ProviderHeaders) -> Authentication {
    let is_true = |names: &[String]| {
        first_present_header(headers, names).is_some_and(|v| v.to_lowercase() == "true")
    };
    let mut auth = Authentication {
        compauth_result: first_present_header(headers, &provider.composite_auth_result)
            .filter(|v| !v.is_empty())
            .map(|v| v.to_lowercase()),
        compauth_reason: first_present_header(headers, &provider.composite_auth_reason),
        is_anonymous_direct_send: is_true(&provider.anonymous_direct_send),
        internal_org_sender: is_true(&provider.internal_org_sender),
        message_directionality: first_present_header(headers, &provider.message_directionality),
        ..Authentication::default()
    };

    // the Authentication-Results header that carries a dmarc verdict, else the first
    let all: Vec<String> = headers
        .get_all("authentication-results")
        .iter()
        .map(decode_rfc2822)
        .collect();
    let results = all
        .iter()
        .find(|h| AUTH_DMARC.is_match(h))
        .or(all.first())
        .map(String::as_str)
        .unwrap_or_default();
    let verdict = |pattern: &Regex| pattern.captures(results).map(|c| c[1].to_lowercase());
    auth.spf_result = verdict(&AUTH_SPF);
    auth.dkim_result = verdict(&AUTH_DKIM);
    auth.dmarc_result = verdict(&AUTH_DMARC);
    if auth.compauth_result.is_none() {
        auth.compauth_result = verdict(&AUTH_COMPAUTH);
    }
    if auth.compauth_reason.is_none() {
        auth.compauth_reason = AUTH_COMPAUTH_REASON
            .captures(results)
            .map(|c| c[1].to_owned());
    }
    auth
}

/// The parenthesized part of a Received header that starts `from host (...)`.
pub fn received_path_item(received: &str) -> Option<String> {
    RECEIVED_IPADDR.captures(received).map(|c| c[1].to_owned())
}

/// `get_received_time`. ace3 passes `re.M` as the start position by mistake, so the search starts
/// at the ninth character, and parses the date with dateutil; dates are read here as RFC 2822
/// writes them, the way mail servers stamp Received headers.
pub fn received_time(received: &str) -> Option<DateTime<Utc>> {
    let start = received.char_indices().nth(8).map(|(i, _)| i)?;
    let caps = RECEIVED_DATE.captures(&received[start..])?;
    parse_date(&caps[1])
}

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// Reads an RFC 2822 date such as `Thu, 28 May 2020 07:53:21 -0700 (PDT)`. A date without a
/// zone is UTC, which is what ace3's container treats a naive time as.
pub fn parse_date(text: &str) -> Option<DateTime<Utc>> {
    // comments, such as the zone name after the offset, aren't part of the date
    let mut clean = String::new();
    let mut depth = 0;
    for c in text.chars() {
        match c {
            '(' => depth += 1,
            ')' if depth > 0 => depth -= 1,
            _ if depth == 0 => clean.push(c),
            _ => {}
        }
    }
    let mut tokens: Vec<&str> = clean
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|t| !t.is_empty())
        .collect();
    // the day of the week is optional
    if tokens
        .first()
        .is_some_and(|t| t.len() >= 3 && t.chars().all(char::is_alphabetic))
    {
        tokens.remove(0);
    }
    let [day, month, year, time, rest @ ..] = tokens.as_slice() else {
        return None;
    };
    let day: u32 = day.parse().ok()?;
    let month = MONTHS
        .iter()
        .position(|m| month.to_lowercase().starts_with(m))? as u32
        + 1;
    let mut year: i32 = year.parse().ok()?;
    if year < 100 {
        year += if year < 50 { 2000 } else { 1900 };
    }
    let mut hms = time.split(':').map(|p| p.parse::<u32>());
    let hour = hms.next()?.ok()?;
    let minute = hms.next()?.ok()?;
    let second = hms.next().transpose().ok()?.unwrap_or(0);
    let naive = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, minute, second)?;
    let offset = rest.first().map_or(Some(0), |zone| zone_offset(zone))?;
    let zone = FixedOffset::east_opt(offset)?;
    let local = zone.from_local_datetime(&naive).single()?;
    Some(local.with_timezone(&Utc))
}

fn zone_offset(zone: &str) -> Option<i32> {
    if let Some(sign) = zone.chars().next().filter(|c| *c == '+' || *c == '-') {
        let digits = &zone[1..];
        if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let hours: i32 = digits[..2].parse().ok()?;
        let minutes: i32 = digits[2..].parse().ok()?;
        let seconds = (TimeDelta::hours(hours.into()) + TimeDelta::minutes(minutes.into()))
            .num_seconds() as i32;
        return Some(if sign == '-' { -seconds } else { seconds });
    }
    let hours = match zone.to_uppercase().as_str() {
        "UT" | "UTC" | "GMT" | "Z" => 0,
        "EST" => -5,
        "EDT" => -4,
        "CST" => -6,
        "CDT" => -5,
        "MST" => -7,
        "MDT" => -6,
        "PST" => -8,
        "PDT" => -7,
        _ => return None,
    };
    Some(hours * 3600)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::py::parse_headers;

    #[test]
    fn received_dates() {
        let header = "by mail-lf1-f52.google.com with SMTP id x27so16720941lfg.9\n        for <a@b.com>; Thu, 28 May 2020 07:53:21 -0700 (PDT)";
        assert_eq!(
            received_time(header).map(|t| t.to_rfc3339()),
            Some("2020-05-28T14:53:21+00:00".to_owned())
        );
        assert_eq!(received_time("from x; not a date"), None);
        assert_eq!(received_time("from x by y"), None);
    }

    #[test]
    fn subdomains() {
        assert!(is_subdomain("mail.company.com", "company.com"));
        assert!(is_subdomain("Company.com", "company.com"));
        assert!(!is_subdomain("company.com", "mail.company.com"));
        assert!(!is_subdomain("evilcompany.com", "company.com"));
    }

    #[test]
    fn first_hop_from_the_perimeter_receipt() {
        let raw = b"Received: from mx.company.com (10.0.0.5) by inside.company.com; Thu, 1 Jan 2020 00:00:00 +0000\n\
Received: from sender.example.net (mail.example.net [93.184.216.34]) by mx.company.com; Thu, 1 Jan 2020 00:00:00 +0000\n\
Received: from laptop (10.13.46.65) by sender.example.net; Thu, 1 Jan 2020 00:00:00 +0000\n\n";
        let headers = parse_headers(raw);
        let hop = resolve_first_hop(&headers, &[], &["company.com".to_owned()]);
        // a documentation address is private to Python, so the hop before it would be skipped
        // as an internal relay; this one is public
        assert_eq!(
            hop,
            FirstHop {
                ip: Some("93.184.216.34".to_owned()),
                helo: Some("sender.example.net".to_owned()),
                from: Some("mail.example.net".to_owned()),
            }
        );
    }

    #[test]
    fn first_hop_ip_from_a_structured_header() {
        assert_eq!(
            extract_first_hop_ip("TenantId=abc;Ip=[2603:10b6::1];Helo=[x]"),
            Some("2603:10b6::1".to_owned())
        );
        assert_eq!(
            normalize_ip_header_value(" [10.0.0.1] "),
            Some("10.0.0.1".to_owned())
        );
    }

    #[test]
    fn tenant_ids_are_canonical() {
        assert_eq!(
            parse_uuid("{CFDDBA29-CA2A-450C-A415-595E7FCCE8E5}"),
            Some("cfddba29-ca2a-450c-a415-595e7fcce8e5".to_owned())
        );
        assert_eq!(parse_uuid("not a guid"), None);
    }
}
