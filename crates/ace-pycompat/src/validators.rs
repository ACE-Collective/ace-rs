//! validators 0.36.0: `url(value, simple_host=...)`, `email(value)` and `domain(value)`, with
//! their other arguments at the defaults, and the `hostname`, `ipv4` and `ipv6` they call.
//!
//! The `@validator` decorator turns a `ValueError`, `TypeError` or `UnicodeError` into a false
//! result, and nothing these call raises anything else, so each returns a bool.
//!
//! The regexes are matched by hand. Python's `re` semantics are kept: `\s` is `str.isspace`, `$`
//! also matches before a final `"\n"`, `re.match` anchors only at the start, and each character
//! class matched with `re.IGNORECASE` is a table of the code points Python's `re` matches it with
//! (`tables/regex_classes.py`), so U+212A KELVIN SIGN, U+017F, U+0130 and U+0131 match `[a-z]`
//! as they do there.

use crate::codecs_idna;
use crate::ipaddress::{ipv4_address, ipv6_address};
use crate::parse::{parse_qs, unquote, urlsplit};
use crate::pystr::is_space;
use crate::tables::in_ranges;
use crate::tables::regex_classes as rc;

fn class(table: &[(u32, u32)], c: char) -> bool {
    in_ranges(table, c as u32)
}

/// The text `$` can end a match on: all of `s`, or `s` without one final `"\n"`. Either is tried.
fn ends(s: &str) -> impl Iterator<Item = &str> {
    std::iter::once(s).chain(s.strip_suffix('\n'))
}

/// `re.match(r"[c]+(\.[c]+)*$", s)`.
fn dotted_atoms(s: &str, table: &[(u32, u32)]) -> bool {
    ends(s).any(|body| {
        !body.is_empty()
            && body
                .split('.')
                .all(|atom| !atom.is_empty() && atom.chars().all(|c| class(table, c)))
    })
}

/// `re.match(r"^([q]|\\[\t.])*$", s)`.
fn quoted_run(body: &str, table: &[(u32, u32)]) -> bool {
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if !matches!(chars.next(), Some('\t' | '.')) {
                return false;
            }
        } else if !class(table, c) {
            return false;
        }
    }
    true
}

/// validators.url's `_username_regex().match(value)`.
fn username_matches(value: &str) -> bool {
    if value
        .chars()
        .next()
        .is_some_and(|c| class(rc::URL_USER_FIRST, c))
    {
        return true;
    }
    dotted_atoms(value, rc::URL_USER_ATOM)
        || ends(value).any(|b| quoted_run(b, rc::URL_USER_QUOTED))
}

/// validators.email's username regex. Its last `$` follows the group, so the first alternative
/// matches a single character.
fn email_username_matches(value: &str) -> bool {
    if ends(value).any(|b| {
        let mut chars = b.chars();
        chars.next().is_some_and(|c| class(rc::EMAIL_FIRST, c)) && chars.next().is_none()
    }) {
        return true;
    }
    if dotted_atoms(value, rc::EMAIL_ATOM) {
        return true;
    }
    // ^"( [q] | \\[\t.] )*"$
    ends(value).any(|body| {
        body.len() >= 2
            && body.starts_with('"')
            && body.ends_with('"')
            && quoted_run(&body[1..body.len() - 1], rc::EMAIL_QUOTED)
    })
}

/// hostname's `_simple_hostname_regex().match(host)`:
/// `^(?!-)[a-z0-9](?:[a-z0-9-]{0,59}[a-z0-9])?(?<!-)$` with re.IGNORECASE.
fn simple_hostname(host: &str) -> bool {
    ends(host).any(|body| {
        let chars: Vec<char> = body.chars().collect();
        let n = chars.len();
        (1..=61).contains(&n)
            && class(rc::HOST_ALNUM, chars[0])
            && class(rc::HOST_ALNUM, chars[n - 1])
            && chars[1..n.saturating_sub(1).max(1)]
                .iter()
                .all(|&c| class(rc::HOST_ALNUM_HYPHEN, c))
    })
}

/// hostname's `_port_regex().match(":" + port)`: 1 to 65535 without a leading zero.
fn port_matches(port: &str) -> bool {
    ends(port).any(|p| {
        !p.is_empty()
            && p.len() <= 5
            && p.bytes().all(|b| b.is_ascii_digit())
            && !p.starts_with('0')
            && p.parse::<u32>().is_ok_and(|v| v <= 65535)
    })
}

/// hostname's `_port_validator(value)`.
fn port_validator(value: &str) -> Option<&str> {
    if value.matches("]:").count() == 1
        && let Some((host, port)) = value.rsplit_once(':')
        && port_matches(port)
    {
        return Some(host.trim_start_matches('[').trim_end_matches(']'));
    }
    if value.matches(':').count() == 1
        && let Some((host, port)) = value.rsplit_once(':')
        && port_matches(port)
    {
        return Some(host);
    }
    None
}

/// `validators.ipv4(value, cidr=False)`.
pub fn ipv4(value: &str) -> bool {
    !value.is_empty() && ipv4_address(value).is_ok()
}

/// `validators.ipv6(value, cidr=False)`.
pub fn ipv6(value: &str) -> bool {
    !value.is_empty() && ipv6_address(value).is_ok()
}

/// `validators.domain(value)`.
pub fn domain(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let Ok(encoded) = codecs_idna::encode(value) else {
        return false;
    };
    if encoded.trim_end_matches('.').chars().count() > 253 {
        return false;
    }
    if value.contains(is_space) || value.contains("__") {
        return false;
    }
    domain_regex(&encoded)
}

/// `^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z]$` with
/// re.IGNORECASE, on the ASCII the idna codec gives.
fn domain_regex(encoded: &str) -> bool {
    let alnum = |b: u8| b.is_ascii_alphanumeric();
    let hyphen = |b: u8| b.is_ascii_alphanumeric() || b == b'-';
    ends(encoded).any(|body| {
        let labels: Vec<&[u8]> = body.as_bytes().split(|&b| b == b'.').collect();
        let Some((last, rest)) = labels.split_last() else {
            return false;
        };
        !rest.is_empty()
            && rest.iter().all(|l| {
                (1..=63).contains(&l.len())
                    && alnum(l[0])
                    && alnum(l[l.len() - 1])
                    && l.iter().all(|&b| hyphen(b))
            })
            && (2..=63).contains(&last.len())
            && alnum(last[0])
            && last[last.len() - 1].is_ascii_alphabetic()
            && last.iter().all(|&b| hyphen(b))
    })
}

/// `validators.hostname(value, ...)` with consider_tld, private, rfc_1034 and rfc_2782 at their
/// defaults.
fn hostname(
    value: &str,
    skip_ipv6_addr: bool,
    skip_ipv4_addr: bool,
    may_have_port: bool,
    maybe_simple: bool,
) -> bool {
    if value.is_empty() {
        return false;
    }
    let check = |host: &str| {
        (maybe_simple && simple_hostname(host))
            || domain(host)
            || (!skip_ipv4_addr && ipv4(host))
            || (!skip_ipv6_addr && ipv6(host))
    };
    if may_have_port && let Some(host) = port_validator(value).filter(|h| !h.is_empty()) {
        return check(host);
    }
    check(value)
}

fn confirm_ipv6_skip(value: &str) -> bool {
    value.matches(':').count() < 2 || !value.starts_with('[')
}

fn validate_auth_segment(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let colons = value.matches(':').count();
    if colons > 1 {
        return username_matches(&unquote(value));
    }
    if colons < 1 {
        return username_matches(value);
    }
    let Some((username, password)) = value.rsplit_once(':') else {
        return false;
    };
    username_matches(username) && !password.contains(['/', '?', '#', '@'])
}

fn validate_netloc(value: &str, simple_host: bool) -> bool {
    if value.is_empty() {
        return false;
    }
    let ats = value.matches('@').count();
    if ats > 1 {
        return false;
    }
    let (auth, host) = match value.rsplit_once('@') {
        Some((auth, host)) => (Some(auth), host),
        None => (None, value),
    };
    let skip = confirm_ipv6_skip(host);
    let host = if skip || value.contains("]:") {
        host.to_owned()
    } else {
        host.trim_start_matches('[').replacen(']', "", 1)
    };
    hostname(&host, skip, false, true, simple_host) && auth.is_none_or(validate_auth_segment)
}

fn validate_optionals(path: &str, query: &str, fragment: &str) -> bool {
    let mut ok = true;
    if !path.is_empty() {
        ok &= ends(path).any(|b| !b.is_empty() && b.chars().all(|c| class(rc::URL_PATH, c)));
    }
    ok && validate_query(query)
        && (fragment.is_empty() || fragment.chars().all(|c| class(rc::URL_FRAGMENT, c)))
}

/// The query only matters by raising: `parse_qs` with strict parsing raises `ValueError` for a
/// field without `=`, and the second call happens only when the first finds something.
fn validate_query(query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    match parse_qs(query, false, true, "&") {
        Err(_) => false,
        Ok(r) if r.is_empty() => true,
        Ok(_) => parse_qs(query, false, true, ";").is_ok(),
    }
}

const SCHEMES: &[&str] = &[
    "file", "ftp", "ftps", "git", "http", "https", "irc", "rtmp", "rtmps", "rtsp", "sftp", "ssh",
    "telnet",
];

/// `validators.url(value, simple_host=simple_host)`.
pub fn url(value: &str, simple_host: bool) -> bool {
    if value.is_empty() || value.contains(is_space) {
        return false;
    }
    let Ok(split) = urlsplit(value, "", true) else {
        return false;
    };
    let is_local_file = split.scheme == "file" && matches!(split.netloc.as_str(), "" | "localhost");
    SCHEMES.contains(&split.scheme.as_str())
        && (is_local_file || validate_netloc(&split.netloc, simple_host))
        && validate_optionals(&split.path, &split.query, &split.fragment)
}

/// `validators.email(value)`.
pub fn email(value: &str) -> bool {
    if value.is_empty() || value.matches('@').count() != 1 {
        return false;
    }
    let Some((username, domain_part)) = value.rsplit_once('@') else {
        return false;
    };
    if username.chars().count() > 64 || domain_part.chars().count() > 253 {
        return false;
    }
    email_username_matches(username) && hostname(domain_part, true, true, false, false)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::testdata::{Mismatches, s};

    #[test]
    fn validators_match_python() {
        let data: Value =
            crate::testdata::load("validators", include_str!("../tests/data/validators.json"));
        let mut m = Mismatches::new("validators");
        for case in data.as_array().unwrap() {
            let x = s(case, "s");
            let got = json!({
                "s": x,
                "url": url(x, false),
                "url_simple": url(x, true),
                "email": email(x),
                "domain": domain(x),
            });
            m.check(x, &got, case);
        }
        m.finish();
    }
}
