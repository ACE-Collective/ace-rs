//! Which IP addresses are private or globally reachable, as Python 3.14's `ipaddress` decides.
//!
//! ace3's modules ask Python, and Rust's `std::net` answers differently for some ranges (Rust
//! has no `is_global` on stable, and Python treats `100.64.0.0/10` as neither private nor
//! global), so ported modules use these to keep ace3's choices.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IPv4 blocks IANA lists as not globally reachable (`_IPv4Constants._private_networks`).
const PRIVATE_V4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 0, 0, 0), 24),
    (Ipv4Addr::new(192, 0, 0, 170), 31),
    (Ipv4Addr::new(192, 0, 2, 0), 24),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(198, 18, 0, 0), 15),
    (Ipv4Addr::new(198, 51, 100, 0), 24),
    (Ipv4Addr::new(203, 0, 113, 0), 24),
    (Ipv4Addr::new(240, 0, 0, 0), 4),
    (Ipv4Addr::new(255, 255, 255, 255), 32),
];

const PRIVATE_V4_EXCEPTIONS: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(192, 0, 0, 9), 32),
    (Ipv4Addr::new(192, 0, 0, 10), 32),
];

/// Shared address space: neither private nor global in Python.
const SHARED_V4: (Ipv4Addr, u8) = (Ipv4Addr::new(100, 64, 0, 0), 10);

const PRIVATE_V6: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 128),
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 128),
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0), 96),
    (Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0), 48),
    (Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0), 64),
    (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16),
    (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20),
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
];

const PRIVATE_V6_EXCEPTIONS: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 1), 128),
    (Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 2), 128),
    (Ipv6Addr::new(0x2001, 3, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2001, 4, 0x112, 0, 0, 0, 0, 0), 48),
    (Ipv6Addr::new(0x2001, 0x20, 0, 0, 0, 0, 0, 0), 28),
    (Ipv6Addr::new(0x2001, 0x30, 0, 0, 0, 0, 0, 0), 28),
];

fn in_v4(ip: Ipv4Addr, (net, len): (Ipv4Addr, u8)) -> bool {
    let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
    u32::from(ip) & mask == u32::from(net) & mask
}

fn in_v6(ip: Ipv6Addr, (net, len): (Ipv6Addr, u8)) -> bool {
    let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
    u128::from(ip) & mask == u128::from(net) & mask
}

/// `ipaddress.ip_address(ip).is_private`.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            PRIVATE_V4.iter().any(|&net| in_v4(v4, net))
                && !PRIVATE_V4_EXCEPTIONS.iter().any(|&net| in_v4(v4, net))
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_private(IpAddr::V4(v4)),
            None => {
                PRIVATE_V6.iter().any(|&net| in_v6(v6, net))
                    && !PRIVATE_V6_EXCEPTIONS.iter().any(|&net| in_v6(v6, net))
            }
        },
    }
}

/// `ipaddress.ip_address(ip).is_global`.
pub fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !in_v4(v4, SHARED_V4) && !is_private(ip),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_global(IpAddr::V4(v4)),
            None => !is_private(ip),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an IP address")
    }

    #[test]
    fn ranges_follow_python() {
        for private in [
            "10.1.2.3",
            "127.0.0.1",
            "192.168.1.1",
            "::1",
            "fd00::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_private(ip(private)), "{private}");
            assert!(!is_global(ip(private)), "{private}");
        }
        for global in ["8.8.8.8", "2606:4700::1111", "192.0.0.9", "2001:4:112::1"] {
            assert!(!is_private(ip(global)), "{global}");
            assert!(is_global(ip(global)), "{global}");
        }
        // shared address space is neither
        assert!(!is_private(ip("100.64.1.1")));
        assert!(!is_global(ip("100.64.1.1")));
    }
}
