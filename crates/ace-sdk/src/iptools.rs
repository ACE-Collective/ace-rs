//! `iptools` 0.7.0's `IpRange`, which ace3's network identifier builds from each row of its CSV and
//! asks whether an address is in it, and which ace3's `ipv4` observable matches a global exclusion
//! written as a range with (`crate::exclusions`).
//!
//! A range is CIDR notation, IPv4 (`10/8`, `10.1.0.0/16`) or IPv6 (`2001:db8::/32`), an address and
//! a dotted netmask (`192.168.1.0/255.255.255.0`), or one address. iptools reads a short IPv4
//! address as Python's `inet_aton` doesn't: `10.1` is `10.0.0.1`, and `10.1/16`'s network is
//! `10.1.0.0`. Its patterns use Python's `\d`, which takes any Unicode digit; here a digit is ASCII,
//! so a range written with other digits is refused where iptools would read it.

/// A range of addresses, as numbers: an IPv4 address is below 2^32.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRange {
    start: u128,
    end: u128,
}

const MAX_IPV4: u128 = 0xffff_ffff;
/// `::ffff:0:0/96`, the IPv4-mapped IPv6 addresses.
const MAPPED: (u128, u128) = (0xffff_0000_0000, 0xffff_ffff_ffff);

/// What `$` allows: the text, less one newline at its end.
fn body(s: &str) -> &str {
    s.strip_suffix('\n').unwrap_or(s)
}

/// `int(q)` of a part a pattern has already checked: Python's `int` ignores surrounding whitespace.
fn int(q: &str, radix: u32) -> Option<u128> {
    let q = q.trim_matches(|c: char| c.is_ascii_whitespace());
    if q.is_empty() {
        return None;
    }
    u128::from_str_radix(q, radix).ok()
}

/// `^(\d{1,3}\.){0,3}\d{1,3}$`.
fn dotted_quad_shape(s: &str) -> bool {
    let parts: Vec<&str> = body(s).split('.').collect();
    parts.len() <= 4
        && parts
            .iter()
            .all(|p| (1..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
}

/// `ipv4.validate_ip`.
fn v4_validate_ip(s: &str) -> bool {
    dotted_quad_shape(s) && s.split('.').all(|q| int(q, 10).is_some_and(|n| n <= 255))
}

/// `ipv4.ip2long`: a short address's last part is its host, the rest its network.
fn v4_ip2long(ip: &str) -> Option<u128> {
    if !v4_validate_ip(ip) {
        return None;
    }
    let mut quads: Vec<u128> = ip.split('.').map(|q| int(q, 10).unwrap_or(0)).collect();
    if quads.len() == 1 {
        quads.extend([0, 0, 0]);
    } else if quads.len() < 4 {
        let host = quads.pop().unwrap_or(0);
        while quads.len() < 3 {
            quads.push(0);
        }
        quads.push(host);
    }
    Some(quads.iter().fold(0, |acc, q| (acc << 8) | q))
}

/// `ipv4.ip2network`: a short address is all network, `127.1` being `127.1.0.0`.
fn v4_ip2network(ip: &str) -> Option<u128> {
    if !v4_validate_ip(ip) {
        return None;
    }
    let quads: Vec<&str> = ip.split('.').collect();
    Some((0..4).fold(0, |acc, i| {
        (acc << 8) | quads.get(i).and_then(|q| int(q, 10)).unwrap_or(0)
    }))
}

fn v4_block(network: u128, prefix: u32) -> (u128, u128) {
    let shift = 32 - prefix;
    let start = (network >> shift) << shift;
    (start, start | ((1u128 << shift) - 1))
}

/// `ipv4.validate_cidr` and `cidr2block`.
fn v4_cidr(s: &str) -> Option<(u128, u128)> {
    let (ip, mask) = body(s).split_once('/')?;
    let mask_ok = (1..=2).contains(&mask.len()) && mask.bytes().all(|b| b.is_ascii_digit());
    if !mask_ok || !dotted_quad_shape(ip) || !v4_validate_ip(ip) {
        return None;
    }
    let (ip, mask) = s.split_once('/')?;
    let prefix = u32::try_from(int(mask, 10)?).ok()?;
    if prefix > 32 {
        return None;
    }
    Some(v4_block(v4_ip2network(ip)?, prefix))
}

/// `ipv4.validate_netmask`: ones, then zeros.
fn v4_validate_netmask(s: &str) -> bool {
    v4_validate_ip(s)
        && v4_ip2network(s).is_some_and(|n| (n as u32).leading_ones() == (n as u32).count_ones())
}

/// `ipv4.validate_subnet` and `subnet2block`. `None` where iptools raises too, as for two `/`.
fn v4_subnet(s: &str) -> Option<(u128, u128)> {
    let (ip, mask) = s.split_once('/')?;
    if mask.contains('/') || !v4_validate_ip(ip) || !v4_validate_netmask(mask) {
        return None;
    }
    let prefix = v4_ip2network(mask)?.count_ones();
    Some(v4_block(v4_ip2network(ip)?, prefix))
}

/// `^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$`, or with `lower` the CIDR pattern's lowercase
/// hex, for the part before any `/`.
fn hex_shape(s: &str, lower: bool) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    (3..=8).contains(&parts.len())
        && parts.iter().all(|p| {
            p.len() <= 4
                && p.bytes().all(|b| {
                    b.is_ascii_digit()
                        || (b'a'..=b'f').contains(&b)
                        || (!lower && (b'A'..=b'F').contains(&b))
                })
        })
}

/// `ipv6.validate_ip`.
fn v6_validate_ip(s: &str) -> bool {
    if hex_shape(body(s), false) {
        return s.split("::").count() <= 2;
    }
    // ^([0-9a-f]{0,4}:){2,6}(\d{1,3}\.){0,3}\d{1,3}$
    let parts: Vec<&str> = body(s).split(':').collect();
    let dotted = (3..=7).contains(&parts.len())
        && parts[..parts.len() - 1].iter().all(|p| {
            p.len() <= 4
                && p.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        && dotted_quad_shape(parts[parts.len() - 1]);
    if !dotted || s.split("::").count() > 2 {
        return false;
    }
    let last = s.rsplit(':').next().unwrap_or_default();
    last.split('.')
        .all(|q| int(q, 10).is_some_and(|n| n <= 255))
}

/// `ipv6.ip2long`.
fn v6_ip2long(ip: &str) -> Option<u128> {
    if !v6_validate_ip(ip) {
        return None;
    }
    let mut ip = ip.to_owned();
    if ip.contains('.') {
        let mut chunks: Vec<String> = ip.split(':').map(str::to_owned).collect();
        let v4 = v4_ip2long(&chunks.pop()?)?;
        chunks.push(format!("{:x}", (v4 >> 16) & 0xffff));
        chunks.push(format!("{:x}", v4 & 0xffff));
        ip = chunks.join(":");
    }
    let halves: Vec<&str> = ip.split("::").collect();
    let mut hextets: Vec<&str> = halves[0].split(':').collect();
    if halves.len() == 2 {
        let h2: Vec<&str> = halves[1].split(':').collect();
        let zeros = 8usize.saturating_sub(hextets.len() + h2.len());
        hextets.extend(std::iter::repeat_n("0", zeros));
        hextets.extend(h2);
    }
    let mut long: u128 = 0;
    for h in hextets {
        let value = if h.is_empty() { 0 } else { int(h, 16)? };
        long = long.checked_shl(16)? | value;
    }
    Some(long)
}

/// `ipv6.validate_cidr` and `cidr2block`.
fn v6_cidr(s: &str) -> Option<(u128, u128)> {
    let (ip, mask) = body(s).split_once('/')?;
    let mask_ok = (1..=3).contains(&mask.len()) && mask.bytes().all(|b| b.is_ascii_digit());
    if !mask_ok || !hex_shape(ip, true) || !v6_validate_ip(ip) {
        return None;
    }
    let (ip, mask) = s.split_once('/')?;
    let prefix = u32::try_from(int(mask, 10)?).ok()?;
    if prefix > 128 {
        return None;
    }
    let ip = v6_ip2long(ip)?;
    let shift = 128 - prefix;
    let start = if shift == 128 {
        0
    } else {
        (ip >> shift) << shift
    };
    let mask = if shift == 128 {
        u128::MAX
    } else {
        (1u128 << shift) - 1
    };
    Some((start, start | mask))
}

/// iptools' `_address2long`: IPv4, then IPv6.
pub fn address2long(address: &str) -> Option<u128> {
    v4_ip2long(address).or_else(|| v6_ip2long(address))
}

impl IpRange {
    /// `IpRange(start)`, or `None` where iptools raises, as for an address it can't read.
    pub fn new(spec: &str) -> Option<IpRange> {
        let (start, end) = if let Some(block) = v4_cidr(spec).or_else(|| v6_cidr(spec)) {
            block
        } else if spec.contains('/') {
            // not a netmask either: iptools then reads the whole text as one address, which fails
            v4_subnet(spec)?
        } else {
            let address = address2long(spec)?;
            (address, address)
        };
        Some(IpRange {
            start: start.min(end),
            end: start.max(end),
        })
    }

    /// `item in range`, or `None` where iptools raises a `TypeError` because it can't read the
    /// address. An IPv4-mapped IPv6 address is in an IPv4 range when its IPv4 address is.
    pub fn contains(&self, address: &str) -> Option<bool> {
        let mut item = address2long(address)?;
        if self.end <= MAX_IPV4 && item > MAX_IPV4 && (MAPPED.0..=MAPPED.1).contains(&item) {
            item &= MAX_IPV4;
        }
        Some(self.start <= item && item <= self.end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(spec: &str) -> (u128, u128) {
        let r = IpRange::new(spec).unwrap_or_else(|| panic!("{spec} reads"));
        (r.start, r.end)
    }

    #[test]
    fn ranges_read_as_iptools_reads_them() {
        assert_eq!(range("10/8"), (0x0a00_0000, 0x0aff_ffff));
        assert_eq!(range("127.1/16"), (0x7f01_0000, 0x7f01_ffff));
        assert_eq!(range("127.0.0.1/32"), (0x7f00_0001, 0x7f00_0001));
        assert_eq!(range("0.0.0.0/0"), (0, 0xffff_ffff));
        assert_eq!(
            range("192.168.1.0/255.255.255.0"),
            (0xc0a8_0100, 0xc0a8_01ff)
        );
        assert_eq!(range("10.1"), (0x0a00_0001, 0x0a00_0001));
        assert_eq!(range("::/0"), (0, u128::MAX));
        assert_eq!(range("2001:db8::/32").0, 0x2001_0db8 << 96);
        assert!(IpRange::new("10.0.0.256").is_none());
        assert!(IpRange::new("10.0.0.0/33").is_none());
        assert!(IpRange::new("1.2.3.4/255.0.255.0").is_none());
        assert!(IpRange::new("2001:DB8::/32").is_none());
        assert!(IpRange::new("nonsense").is_none());
    }

    #[test]
    fn membership() {
        let r = IpRange::new("10.0.0.0/8").expect("reads");
        assert_eq!(r.contains("10.1.2.3"), Some(true));
        assert_eq!(r.contains("::ffff:10.1.2.3"), Some(true));
        assert_eq!(r.contains("::ffff:a01:203"), Some(true));
        assert_eq!(r.contains("11.0.0.0"), Some(false));
        assert_eq!(r.contains("fe80::1%eth0"), None);
        let v6 = IpRange::new("2001:db8::/32").expect("reads");
        assert_eq!(v6.contains("2001:db8::5"), Some(true));
        assert_eq!(v6.contains("2001:DB8::5"), Some(true));
        assert_eq!(v6.contains("10.0.0.1"), Some(false));
    }
}
