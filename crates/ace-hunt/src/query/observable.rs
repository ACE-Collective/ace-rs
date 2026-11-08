//! An observable a hunt makes, and what ace3's observable classes do to a value when one is made
//! (`saq.observables.generator.create_observable` and the classes `etc/saq.default.yaml` maps
//! types to): some refuse a value, which drops the observable, and some change it.
//!
//! Ported are the classes of the types the signatures' Splunk hunts map to and the hash types:
//! `ip`, `ipv4`, `email_address`, `message_id`, `fqdn`, `url`, `hostname`, `asset`, `user`,
//! `user_agent`, `uri_path`, `file_location`, `md5`, `sha1` and `sha256`. Any other type takes its
//! value as it is, as ace3's `DefaultObservable` and the classes that only store it do. ace3's
//! `fqdn` encodes a non-ASCII name with Python's IDNA 2003 codec before checking it; here a
//! non-ASCII name is refused.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::Serialize;

/// An observable as a hunt submits it, the fields of ace3's `Observable` that a hunt sets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Observable {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
    #[serde(serialize_with = "py_time")]
    pub time: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub directives: Vec<String>,
    pub display_type: Option<String>,
    pub display_value: Option<String>,
    pub volatile: bool,
    pub relationships: Vec<Relationship>,
}

fn py_time<S: serde::Serializer>(time: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error> {
    match time {
        Some(t) => s.serialize_str(&crate::query::isoformat(t)),
        None => s.serialize_none(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Relationship {
    #[serde(rename = "type")]
    pub kind: String,
    pub target: Target,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Target {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

impl Observable {
    /// `create_observable`: None when the type's class refuses the value.
    pub fn create(
        kind: &str,
        value: &str,
        volatile: bool,
        email: EmailNormalizer,
    ) -> Option<Observable> {
        Some(Observable {
            kind: kind.to_owned(),
            value: normalize(kind, value, email)?,
            time: None,
            tags: Vec::new(),
            directives: Vec::new(),
            display_type: None,
            display_value: None,
            volatile,
            relationships: Vec::new(),
        })
    }

    /// ace3's `Observable.__eq__`: the same type and value, compared without case for a caseless
    /// type, and the same time when either has one.
    pub fn same(&self, other: &Observable) -> bool {
        self.kind == other.kind
            && self.time == other.time
            && same_value(&self.kind, &self.value, &other.value)
    }

    /// `add_tag`, which keeps one of each.
    pub fn add_tag(&mut self, tag: &str) {
        if !self.tags.iter().any(|t| t == tag) {
            self.tags.push(tag.to_owned());
        }
    }

    /// `add_directive`, which keeps one of each.
    pub fn add_directive(&mut self, directive: &str) {
        if !self.directives.iter().any(|d| d == directive) {
            self.directives.push(directive.to_owned());
        }
    }
}

/// The types whose class is a `CaselessObservable`.
fn caseless(kind: &str) -> bool {
    matches!(kind, "email_address" | "asset" | "md5" | "sha1" | "sha256")
}

/// `CaselessObservable._compare_value`: both casefolded. Python also NFKD-normalizes, which only
/// matters for values outside ASCII; those are compared lowercased.
pub fn same_value(kind: &str, a: &str, b: &str) -> bool {
    if caseless(kind) {
        a.to_lowercase() == b.to_lowercase()
    } else {
        a == b
    }
}

/// Python's `str.strip()`: whitespace by Unicode's definition.
fn strip(value: &str) -> &str {
    value.trim_matches(char::is_whitespace)
}

const EMPTY_MD5: &str = "d41d8cd98f00b204e9800998ecf8427e";
const EMPTY_SHA1: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// ace3's `normalize_email_address` (`saq/email.py`), which parses the address as Python's
/// `email.utils.parseaddr` does. The hunter passes the email module's port of it.
pub type EmailNormalizer = fn(&str) -> Option<String>;

/// What the type's class keeps of `value`, or None when it refuses it.
pub fn normalize(kind: &str, value: &str, email: EmailNormalizer) -> Option<String> {
    match kind {
        "ip" => {
            let v = strip(value);
            ip_address(v).map(|_| v.to_owned())
        }
        // IPv4Address is checked on the value as given, which a space fails
        "ipv4" => ipv4_address(value).map(|_| strip(value).to_owned()),
        "email_address" => {
            if !value.contains('@') {
                return None;
            }
            Some(email(value).unwrap_or_else(|| value.to_owned()))
        }
        "message_id" => {
            if !value.contains('@') {
                return None;
            }
            let mut id = strip(value).to_owned();
            if !id.starts_with('<') {
                id.insert(0, '<');
            }
            if !id.ends_with('>') {
                id.push('>');
            }
            Some(id)
        }
        "fqdn" => domain(value).then(|| strip(value).to_owned()),
        "url" => (!url_missing_host(value)).then(|| value.to_owned()),
        "hostname" | "asset" | "user_agent" | "uri_path" => Some(strip(value).to_owned()),
        "user" => {
            let v = strip(value);
            Some(v.rsplit('\\').next().unwrap_or(v).to_owned())
        }
        "file_location" => {
            let (host, path) = value.split_once('@')?;
            (!strip(host).is_empty() && !strip(path).is_empty()).then(|| value.to_owned())
        }
        "md5" => hash(value, EMPTY_MD5),
        "sha1" => hash(value, EMPTY_SHA1),
        "sha256" => hash(value, EMPTY_SHA256),
        _ => Some(value.to_owned()),
    }
}

/// `validate_hash_value`: not all zeros, and not the hash of empty content.
fn hash(value: &str, empty: &str) -> Option<String> {
    let v = strip(value);
    if v.chars().all(|c| c == '0') || v.to_lowercase() == empty {
        return None;
    }
    Some(v.to_owned())
}

/// Python's `ipaddress.ip_address` on text: dotted IPv4 with no leading zeros, or IPv6 with an
/// optional scope.
fn ip_address(value: &str) -> Option<IpAddr> {
    if let Some(v4) = ipv4_address(value) {
        return Some(IpAddr::V4(v4));
    }
    let (address, scope) = match value.split_once('%') {
        Some((a, s)) if !s.is_empty() && !s.contains('%') => (a, Some(s)),
        Some(_) => return None,
        None => (value, None),
    };
    let _ = scope;
    address.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6)
}

/// `ipaddress.IPv4Address`: four decimal octets of at most three digits, no leading zero.
fn ipv4_address(value: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (octet, part) in octets.iter_mut().zip(&parts) {
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        *octet = part.parse().ok()?;
    }
    Some(Ipv4Addr::from(octets))
}

/// validators 0.36's `domain`, as `FQDNObservable` calls it.
fn domain(value: &str) -> bool {
    static DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z]$")
            .expect("a valid pattern")
    });
    static SPACE_OR_UNDERSCORES: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\s|__+").expect("a valid pattern"));
    if value.is_empty() || !value.is_ascii() {
        return false;
    }
    if value.trim_end_matches('.').len() > 253 {
        return false;
    }
    !SPACE_OR_UNDERSCORES.is_match(value) && DOMAIN.is_match(value)
}

/// `URLObservable`'s check: an http, https or ftp URL whose host, as a browser reads it, has no
/// letter or digit.
fn url_missing_host(value: &str) -> bool {
    let Some((scheme, rest)) = value.split_once(':') else {
        return false;
    };
    let scheme_ok = !scheme.is_empty()
        && scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c));
    if !scheme_ok {
        return false;
    }
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https" | "ftp") {
        return false;
    }
    let rest: String = rest
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect::<String>()
        .replace('\\', "/");
    let rest = rest.trim_start_matches('/');
    // urlsplit's netloc ends at the first /, ? or #; its hostname drops the userinfo and port
    let netloc = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = netloc.rsplit('@').next().unwrap_or_default();
    let host = if let Some(bracketed) = host.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or_default()
    } else {
        host.split(':').next().unwrap_or_default()
    };
    !host.chars().any(char::is_alphanumeric)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalize(kind: &str, value: &str) -> Option<String> {
        super::normalize(kind, value, |v| Some(v.to_lowercase()))
    }

    #[test]
    fn values_are_kept_or_refused_as_ace3_s_classes_do() {
        assert_eq!(normalize("ip", " 10.1.2.3 ").as_deref(), Some("10.1.2.3"));
        assert_eq!(normalize("ip", "not-an-ip"), None);
        assert_eq!(normalize("ip", "010.1.2.3"), None);
        assert_eq!(normalize("ip", "::1").as_deref(), Some("::1"));
        assert_eq!(normalize("ipv4", " 10.1.2.3"), None);
        assert_eq!(normalize("user", "CORP\\alice").as_deref(), Some("alice"));
        assert_eq!(normalize("message_id", "a@b").as_deref(), Some("<a@b>"));
        assert_eq!(normalize("message_id", "nope"), None);
        assert_eq!(
            normalize("fqdn", "www.example.com").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(normalize("fqdn", "not a domain"), None);
        assert_eq!(normalize("fqdn", "a__b.com"), None);
        assert_eq!(
            normalize("url", " https://example.com/x ").as_deref(),
            Some(" https://example.com/x ")
        );
        assert_eq!(normalize("url", "https:/\\.."), None);
        assert_eq!(normalize("url", "mailto:x"), Some("mailto:x".to_owned()));
        assert_eq!(normalize("sha256", EMPTY_SHA256), None);
        assert_eq!(normalize("md5", "0000"), None);
        assert_eq!(normalize("sha1", " abc ").as_deref(), Some("abc"));
        assert_eq!(normalize("file_location", "host@"), None);
        assert_eq!(normalize("command_line", " x ").as_deref(), Some(" x "));
    }
}
