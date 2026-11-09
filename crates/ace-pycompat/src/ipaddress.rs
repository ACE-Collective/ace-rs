//! `ipaddress.ip_address`, `IPv4Address` and `IPv6Address` on a string, and `str()` of each.
//!
//! A port of Python 3.14's `ipaddress`: an IPv4 address is four ASCII decimal octets without
//! leading zeros; an IPv6 address has at most one `::`, may end in an IPv4 address, and may carry a
//! `%scope` that isn't empty and has no second `%`. Errors are `ipaddress.AddressValueError` with
//! Python's messages, and `ip_address` raises a plain `ValueError`.

use std::fmt;

use crate::PyErr;
use crate::repr::repr;

/// An `IPv4Address`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Address {
    /// The address as an integer.
    pub ip: u32,
}

/// An `IPv6Address`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Address {
    /// The address as an integer.
    pub ip: u128,
    /// The scope after `%`, if there was one.
    pub scope_id: Option<String>,
}

/// What `ip_address` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAddress {
    V4(Ipv4Address),
    V6(Ipv6Address),
}

fn address_error(message: String) -> PyErr {
    PyErr::new("ipaddress", "AddressValueError", message)
}

/// `ipaddress.ip_address(address)`.
pub fn ip_address(address: &str) -> Result<IpAddress, PyErr> {
    if let Ok(a) = ipv4_address(address) {
        return Ok(IpAddress::V4(a));
    }
    if let Ok(a) = ipv6_address(address) {
        return Ok(IpAddress::V6(a));
    }
    Err(PyErr::value_error(format!(
        "{} does not appear to be an IPv4 or IPv6 address",
        repr(address)
    )))
}

/// `ipaddress.IPv4Address(address)`.
pub fn ipv4_address(address: &str) -> Result<Ipv4Address, PyErr> {
    if address.contains('/') {
        return Err(address_error(format!(
            "Unexpected '/' in {}",
            repr(address)
        )));
    }
    ipv4_int_from_string(address).map(|ip| Ipv4Address { ip })
}

fn ipv4_int_from_string(ip_str: &str) -> Result<u32, PyErr> {
    if ip_str.is_empty() {
        return Err(address_error("Address cannot be empty".to_owned()));
    }
    let octets: Vec<&str> = ip_str.split('.').collect();
    if octets.len() != 4 {
        return Err(address_error(format!(
            "Expected 4 octets in {}",
            repr(ip_str)
        )));
    }
    let mut ip = 0_u32;
    for octet in octets {
        let v =
            parse_octet(octet).map_err(|e| address_error(format!("{e} in {}", repr(ip_str))))?;
        ip = (ip << 8) | v;
    }
    Ok(ip)
}

fn parse_octet(octet: &str) -> Result<u32, String> {
    if octet.is_empty() {
        return Err("Empty octet not permitted".to_owned());
    }
    if !octet.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("Only decimal digits permitted in {}", repr(octet)));
    }
    if octet.len() > 3 {
        return Err(format!("At most 3 characters permitted in {}", repr(octet)));
    }
    if octet != "0" && octet.starts_with('0') {
        return Err(format!(
            "Leading zeros are not permitted in {}",
            repr(octet)
        ));
    }
    let v: u32 = octet.parse().unwrap_or(0);
    if v > 255 {
        return Err(format!("Octet {v} (> 255) not permitted"));
    }
    Ok(v)
}

/// `ipaddress.IPv6Address(address)`.
pub fn ipv6_address(address: &str) -> Result<Ipv6Address, PyErr> {
    if address.contains('/') {
        return Err(address_error(format!(
            "Unexpected '/' in {}",
            repr(address)
        )));
    }
    let (addr, scope_id) = match address.split_once('%') {
        None => (address, None),
        Some((addr, scope)) => {
            if scope.is_empty() || scope.contains('%') {
                return Err(address_error(format!(
                    "Invalid IPv6 address: \"{}\"",
                    repr(address)
                )));
            }
            (addr, Some(scope.to_owned()))
        }
    };
    let ip = ipv6_int_from_string(addr)?;
    Ok(Ipv6Address { ip, scope_id })
}

fn ipv6_int_from_string(ip_str: &str) -> Result<u128, PyErr> {
    if ip_str.is_empty() {
        return Err(address_error("Address cannot be empty".to_owned()));
    }
    let len = ip_str.chars().count();
    if len > 45 {
        let shorten = if len > 100 {
            let head: String = ip_str.chars().take(45).collect();
            let tail: String = ip_str.chars().skip(len - 45).collect();
            format!("{head}({} chars elided){tail}", len - 90)
        } else {
            ip_str.to_owned()
        };
        return Err(address_error(format!(
            "At most 45 characters expected in {}",
            repr(&shorten)
        )));
    }
    const HEXTETS: usize = 8;
    const MAX_PARTS: usize = HEXTETS + 1;
    let mut parts: Vec<String> = ip_str
        .splitn(MAX_PARTS + 1, ':')
        .map(str::to_owned)
        .collect();
    if parts.len() < 3 {
        return Err(address_error(format!(
            "At least 3 parts expected in {}",
            repr(ip_str)
        )));
    }
    if parts.last().is_some_and(|p| p.contains('.')) {
        let last = parts.pop().unwrap_or_default();
        let v4 = ipv4_address(&last)
            .map_err(|e| address_error(format!("{} in {}", e.message, repr(ip_str))))?;
        parts.push(format!("{:x}", (v4.ip >> 16) & 0xFFFF));
        parts.push(format!("{:x}", v4.ip & 0xFFFF));
    }
    if parts.len() > MAX_PARTS {
        return Err(address_error(format!(
            "At most {} colons permitted in {}",
            MAX_PARTS - 1,
            repr(ip_str)
        )));
    }
    let mut skip_index = None;
    for (i, part) in parts.iter().enumerate().take(parts.len() - 1).skip(1) {
        if part.is_empty() {
            if skip_index.is_some() {
                return Err(address_error(format!(
                    "At most one '::' permitted in {}",
                    repr(ip_str)
                )));
            }
            skip_index = Some(i);
        }
    }
    let (parts_hi, parts_lo, parts_skipped);
    if let Some(skip) = skip_index {
        let mut hi = skip;
        let mut lo = parts.len() - skip - 1;
        if parts[0].is_empty() {
            hi -= 1;
            if hi != 0 {
                return Err(address_error(format!(
                    "Leading ':' only permitted as part of '::' in {}",
                    repr(ip_str)
                )));
            }
        }
        if parts[parts.len() - 1].is_empty() {
            lo -= 1;
            if lo != 0 {
                return Err(address_error(format!(
                    "Trailing ':' only permitted as part of '::' in {}",
                    repr(ip_str)
                )));
            }
        }
        let skipped = HEXTETS as i64 - (hi + lo) as i64;
        if skipped < 1 {
            return Err(address_error(format!(
                "Expected at most {} other parts with '::' in {}",
                HEXTETS - 1,
                repr(ip_str)
            )));
        }
        parts_hi = hi;
        parts_lo = lo;
        parts_skipped = skipped as u32;
    } else {
        if parts.len() != HEXTETS {
            return Err(address_error(format!(
                "Exactly {HEXTETS} parts expected without '::' in {}",
                repr(ip_str)
            )));
        }
        if parts[0].is_empty() {
            return Err(address_error(format!(
                "Leading ':' only permitted as part of '::' in {}",
                repr(ip_str)
            )));
        }
        if parts[parts.len() - 1].is_empty() {
            return Err(address_error(format!(
                "Trailing ':' only permitted as part of '::' in {}",
                repr(ip_str)
            )));
        }
        parts_hi = parts.len();
        parts_lo = 0;
        parts_skipped = 0;
    }
    let wrap = |e: String| address_error(format!("{e} in {}", repr(ip_str)));
    let mut ip: u128 = 0;
    for part in &parts[..parts_hi] {
        ip = (ip << 16) | parse_hextet(part).map_err(wrap)?;
    }
    ip = ip.checked_shl(16 * parts_skipped).unwrap_or(0);
    for part in &parts[parts.len() - parts_lo..] {
        ip = (ip << 16) | parse_hextet(part).map_err(wrap)?;
    }
    Ok(ip)
}

fn parse_hextet(hextet: &str) -> Result<u128, String> {
    if !hextet.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("Only hex digits permitted in {}", repr(hextet)));
    }
    if hextet.len() > 4 {
        return Err(format!(
            "At most 4 characters permitted in {}",
            repr(hextet)
        ));
    }
    u128::from_str_radix(hextet, 16)
        .map_err(|_| format!("invalid literal for int() with base 16: {}", repr(hextet)))
}

impl fmt::Display for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.ip.to_be_bytes();
        write!(f, "{a}.{b}.{c}.{d}")
    }
}

fn compressed(ip: u128) -> String {
    let hextets: Vec<String> = (0..8)
        .map(|i| format!("{:x}", (ip >> (112 - 16 * i)) & 0xFFFF))
        .collect();
    // _compress_hextets: the longest run of "0" hextets, the first if tied, if longer than one.
    let (mut best_start, mut best_len, mut start, mut len) = (0, 0, 0, 0);
    for (i, h) in hextets.iter().enumerate() {
        if h == "0" {
            if len == 0 {
                start = i;
            }
            len += 1;
            if len > best_len {
                best_len = len;
                best_start = start;
            }
        } else {
            len = 0;
        }
    }
    if best_len > 1 {
        let end = best_start + best_len;
        let mut out: Vec<&str> = hextets[..best_start].iter().map(String::as_str).collect();
        if best_start == 0 {
            out.push("");
        }
        out.push("");
        if end == hextets.len() {
            out.push("");
        }
        out.extend(hextets[end..].iter().map(String::as_str));
        out.join(":")
    } else {
        hextets.join(":")
    }
}

impl Ipv6Address {
    /// `ipv4_mapped`: the IPv4 address in `::ffff:0:0/96`, if it is one.
    pub fn ipv4_mapped(&self) -> Option<Ipv4Address> {
        (self.ip >> 32 == 0xFFFF).then_some(Ipv4Address {
            ip: (self.ip & 0xFFFF_FFFF) as u32,
        })
    }
}

impl fmt::Display for Ipv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ipv4_mapped() {
            Some(v4) => write!(f, "{}:{v4}", compressed(self.ip >> 32))?,
            None => f.write_str(&compressed(self.ip))?,
        }
        match &self.scope_id {
            Some(scope) => write!(f, "%{scope}"),
            None => Ok(()),
        }
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpAddress::V4(a) => a.fmt(f),
            IpAddress::V6(a) => a.fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::testdata::{Mismatches, outcome, s};

    #[test]
    fn addresses_match_python() {
        let data: Value =
            crate::testdata::load("ipaddress", include_str!("../tests/data/ipaddress.json"));
        let mut m = Mismatches::new("ipaddress");
        for case in data.as_array().unwrap() {
            let a = s(case, "s");
            let got = json!({
                "s": a,
                "ip_address": outcome(ip_address(a), |v| json!([matches!(v, IpAddress::V4(_)), v.to_string()])),
                "v4": outcome(ipv4_address(a), |v| json!(v.to_string())),
                "v6": outcome(ipv6_address(a), |v| json!(v.to_string())),
            });
            m.check(a, &got, case);
        }
        m.finish();
    }
}
