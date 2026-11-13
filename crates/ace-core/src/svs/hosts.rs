//! The SVS test hosts: the hosts test runs may target, ace3's `saq/svs/hosts.py`.
//!
//! A launcher registers a run against targets, each a host name and a user name. A target matches a test
//! host when its host name is the host's short or fully qualified name, and its user is one the host lists,
//! or the host lists none. Matching ignores case, and takes `DOMAIN\user`, `user@domain` and `user` as one
//! user (ace3's FR-15).
//!
//! Only `ace_service`'s `svs` writes `svs.test_hosts`, under `svs:admin` with an audit row; this module
//! normalizes what it writes and matches a target against what's there.

use ace_pycompat::pystr;
use sqlx::PgConnection;

/// The platforms a test host can be, as Atomic Red Team names them. A test's `supported_platforms` also
/// names cloud platforms, which aren't hosts.
pub const PLATFORMS: [&str; 3] = ["windows", "linux", "macos"];

pub const MAX_USERNAMES: usize = 100;
pub const MAX_IPS: usize = 100;

/// A field of a test host that can't be used; the message says which and why. ace3's `InvalidTestHost`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidTestHost(pub String);

/// Python's `repr` of a str, as ace3's messages quote what they refuse.
fn repr(value: &str) -> String {
    ace_pycompat::repr::repr(value)
}

/// The short name and the fully qualified name (None without a domain) of a host name, lower case. Refused:
/// an empty name, or one with whitespace, `\`, `/` or `@`, or an empty label.
pub fn split_hostname(value: &str) -> Result<(String, Option<String>), InvalidTestHost> {
    let name = pystr::strip(value).trim_end_matches('.').to_lowercase();
    let refused = || InvalidTestHost(format!("{} is not a host name", repr(value)));
    if name.is_empty() || name.chars().any(pystr::is_space) || name.contains(['\\', '/', '@']) {
        return Err(refused());
    }
    let (short, domain) = match name.split_once('.') {
        Some((short, domain)) => (short, Some(domain)),
        None => (name.as_str(), None),
    };
    if short.is_empty() || domain.is_some_and(|domain| domain.split('.').any(str::is_empty)) {
        return Err(refused());
    }
    let qualified = domain.map(|_| name.clone());
    Ok((short.to_owned(), qualified))
}

/// The bare user name, lower case: `CORP\Alice`, `alice@corp.example` and `alice` are all `alice`.
pub fn normalize_username(value: &str) -> Result<String, InvalidTestHost> {
    let mut name = pystr::strip(value).to_lowercase();
    if let Some((_, user)) = name.rsplit_once('\\') {
        name = user.to_owned();
    }
    if let Some((user, _)) = name.split_once('@') {
        name = user.to_owned();
    }
    if name.is_empty() || name.chars().any(pystr::is_space) {
        return Err(InvalidTestHost(format!(
            "{} is not a user name",
            repr(value)
        )));
    }
    Ok(name)
}

/// An address as Python's `ipaddress` writes it.
pub fn normalize_ip(value: &str) -> Result<String, InvalidTestHost> {
    ace_pycompat::ipaddress::ip_address(pystr::strip(value))
        .map(|address| address.to_string())
        .map_err(|_| InvalidTestHost(format!("{} is not an IP address", repr(value))))
}

/// A test host's fields, normalized and checked (`build_spec`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostSpec {
    pub hostname: String,
    pub fqdn: Option<String>,
    /// Sorted, without repeats.
    pub usernames: Vec<String>,
    /// IPv4 first, then each in order, without repeats.
    pub ips: Vec<String>,
    pub platform: Option<String>,
    pub notes: Option<String>,
}

/// What a test host is made from, as a person gives it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostFields {
    pub hostname: String,
    pub fqdn: Option<String>,
    pub usernames: Vec<String>,
    pub ips: Vec<String>,
    pub platform: Option<String>,
    pub notes: Option<String>,
}

impl HostFields {
    pub fn new(hostname: &str) -> Self {
        HostFields {
            hostname: hostname.to_owned(),
            ..HostFields::default()
        }
    }
}

/// Normalizes and checks a test host: ace3's `build_spec`. A fully qualified hostname sets the fqdn too.
pub fn build_spec(fields: &HostFields) -> Result<HostSpec, InvalidTestHost> {
    let (short, mut qualified) = split_hostname(&fields.hostname)?;
    if let Some(fqdn) = fields.fqdn.as_deref().filter(|fqdn| !fqdn.is_empty()) {
        let (fqdn_short, fqdn_qualified) = split_hostname(fqdn)?;
        let Some(fqdn_qualified) = fqdn_qualified.filter(|_| fqdn_short == short) else {
            return Err(InvalidTestHost(format!(
                "fqdn {} is not a fully qualified name of {}",
                repr(fqdn),
                repr(&short)
            )));
        };
        if qualified
            .as_ref()
            .is_some_and(|qualified| *qualified != fqdn_qualified)
        {
            return Err(InvalidTestHost(format!(
                "hostname {} and fqdn {} name different hosts",
                repr(&fields.hostname),
                repr(fqdn)
            )));
        }
        qualified = Some(fqdn_qualified);
    }
    if fields.usernames.len() > MAX_USERNAMES {
        return Err(InvalidTestHost(format!(
            "at most {MAX_USERNAMES} usernames"
        )));
    }
    if fields.ips.len() > MAX_IPS {
        return Err(InvalidTestHost(format!("at most {MAX_IPS} ips")));
    }
    let platform = fields
        .platform
        .as_deref()
        .map(|platform| pystr::strip(platform).to_lowercase())
        .filter(|platform| !platform.is_empty());
    if let Some(platform) = &platform
        && !PLATFORMS.contains(&platform.as_str())
    {
        return Err(InvalidTestHost(format!(
            "platform {} is not one of {}",
            repr(platform),
            PLATFORMS.join(", ")
        )));
    }
    let mut usernames = fields
        .usernames
        .iter()
        .map(|name| normalize_username(name))
        .collect::<Result<Vec<_>, _>>()?;
    usernames.sort();
    usernames.dedup();
    let mut ips = fields
        .ips
        .iter()
        .map(|ip| normalize_ip(ip))
        .collect::<Result<Vec<_>, _>>()?;
    ips.sort_by(|a, b| (a.contains(':'), a).cmp(&(b.contains(':'), b)));
    ips.dedup();
    let notes = fields
        .notes
        .as_deref()
        .map(pystr::strip)
        .filter(|notes| !notes.is_empty())
        .map(str::to_owned);
    Ok(HostSpec {
        hostname: short,
        fqdn: qualified,
        usernames,
        ips,
        platform,
        notes,
    })
}

/// A test host, as matching reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedHost {
    pub id: i64,
    pub hostname: String,
    pub fqdn: Option<String>,
    pub usernames: Vec<String>,
    pub platform: Option<String>,
}

/// How a target matched the test hosts: ace3's `TargetMatch`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetMatch {
    pub host: Option<MatchedHost>,
    /// The host lists the target's user, or lists none.
    pub user_allowed: bool,
    /// Why it didn't match, for the refusal.
    pub reason: Option<String>,
}

impl TargetMatch {
    pub fn matched(&self) -> bool {
        self.host.is_some() && self.user_allowed
    }

    fn refused(host: Option<MatchedHost>, reason: String) -> Self {
        TargetMatch {
            host,
            user_allowed: false,
            reason: Some(reason),
        }
    }
}

/// Finds the test host a run's target names: ace3's `match_target`. Its hostname may be the short or the
/// fully qualified name; a fully qualified one must be the host's fqdn when the host has one, so a production
/// host that shares a short name in another domain never matches. Without a username the target matches
/// only a host that lists no users.
pub async fn match_target(
    conn: &mut PgConnection,
    hostname: &str,
    username: Option<&str>,
) -> Result<TargetMatch, sqlx::Error> {
    let Ok((short, qualified)) = split_hostname(hostname) else {
        return Ok(TargetMatch::refused(
            None,
            format!("{} is not a host name", repr(hostname)),
        ));
    };
    let host = sqlx::query_as!(
        MatchedHost,
        "SELECT id, hostname, fqdn, usernames, platform FROM svs.test_hosts WHERE hostname = $1",
        short,
    )
    .fetch_optional(&mut *conn)
    .await?;
    let Some(host) = host else {
        return Ok(TargetMatch::refused(
            None,
            format!("{short} is not a test host"),
        ));
    };
    if let (Some(qualified), Some(fqdn)) = (&qualified, &host.fqdn)
        && qualified != fqdn
    {
        let reason = format!("{qualified} is not test host {fqdn}");
        return Ok(TargetMatch::refused(Some(host), reason));
    }
    if host.usernames.is_empty() {
        return Ok(TargetMatch {
            host: Some(host),
            user_allowed: true,
            reason: None,
        });
    }
    let Some(username) = username else {
        let reason = format!(
            "test host {} lists its users and no user was given",
            host.hostname
        );
        return Ok(TargetMatch::refused(Some(host), reason));
    };
    let user = match normalize_username(username) {
        Ok(user) => user,
        Err(_) => {
            let reason = format!("{} is not a user name", repr(username));
            return Ok(TargetMatch::refused(Some(host), reason));
        }
    };
    if !host.usernames.contains(&user) {
        let reason = format!("{user} is not a user of test host {}", host.hostname);
        return Ok(TargetMatch::refused(Some(host), reason));
    }
    Ok(TargetMatch {
        host: Some(host),
        user_allowed: true,
        reason: None,
    })
}

/// ace3's tests/saq/svs/test_hosts.py's cases that need no database; the rest are `ace-service`'s.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_a_hostname() {
        for (value, expected) in [
            ("WIN10-01", ("win10-01", None)),
            (
                "win10-01.Corp.Example.",
                ("win10-01", Some("win10-01.corp.example")),
            ),
            ("  host  ", ("host", None)),
        ] {
            assert_eq!(
                split_hostname(value),
                Ok((expected.0.to_owned(), expected.1.map(str::to_owned))),
                "{value}"
            );
        }
    }

    #[test]
    fn split_hostname_rejects() {
        for value in [
            "  ",
            "a b",
            "corp\\host",
            "host/x",
            "user@host",
            ".corp",
            "host..corp",
        ] {
            assert!(split_hostname(value).is_err(), "{value}");
        }
    }

    #[test]
    fn normalize_a_username() {
        for value in ["ALICE", "CORP\\Alice", "alice@corp.example", " alice "] {
            assert_eq!(normalize_username(value), Ok("alice".to_owned()), "{value}");
        }
    }

    fn fields(hostname: &str) -> HostFields {
        HostFields::new(hostname)
    }

    #[test]
    fn build_a_spec() {
        let spec = build_spec(&HostFields {
            usernames: vec![
                "CORP\\Bob".into(),
                "alice".into(),
                "bob@corp.example".into(),
            ],
            ips: vec!["10.0.0.5".into(), "::1".into(), "10.0.0.5".into()],
            platform: Some("Windows".into()),
            notes: Some("  lab 3  ".into()),
            ..fields("WIN10-01.corp.example")
        })
        .expect("a spec");
        assert_eq!(
            (spec.hostname.as_str(), spec.fqdn.as_deref()),
            ("win10-01", Some("win10-01.corp.example"))
        );
        assert_eq!(spec.usernames, ["alice", "bob"]);
        assert_eq!(spec.ips, ["10.0.0.5", "::1"]);
        assert_eq!(
            (spec.platform.as_deref(), spec.notes.as_deref()),
            (Some("windows"), Some("lab 3"))
        );
        let fqdn = build_spec(&HostFields {
            fqdn: Some("WIN10-01.corp.example".into()),
            ..fields("win10-01")
        })
        .expect("a spec");
        assert_eq!(fqdn.fqdn.as_deref(), Some("win10-01.corp.example"));
        let platform = build_spec(&HostFields {
            platform: Some(String::new()),
            ..fields("win10-01")
        })
        .expect("a spec");
        assert_eq!(platform.platform, None);
    }

    #[test]
    fn build_spec_rejects() {
        let cases: Vec<(HostFields, &str)> = vec![
            (
                HostFields {
                    fqdn: Some("other.corp.example".into()),
                    ..fields("win10-01")
                },
                "is not a fully qualified name of",
            ),
            (
                HostFields {
                    fqdn: Some("win10-01".into()),
                    ..fields("win10-01")
                },
                "is not a fully qualified name of",
            ),
            (
                HostFields {
                    fqdn: Some("win10-01.b.example".into()),
                    ..fields("win10-01.a.example")
                },
                "name different hosts",
            ),
            (
                HostFields {
                    ips: vec!["10.0.0.300".into()],
                    ..fields("win10-01")
                },
                "is not an IP address",
            ),
            (
                HostFields {
                    usernames: vec!["CORP\\".into()],
                    ..fields("win10-01")
                },
                "is not a user name",
            ),
            (
                HostFields {
                    platform: Some("iaas".into()),
                    ..fields("win10-01")
                },
                "is not one of windows, linux, macos",
            ),
            (
                HostFields {
                    usernames: vec!["u".into(); 101],
                    ..fields("win10-01")
                },
                "at most 100 usernames",
            ),
        ];
        for (fields, message) in cases {
            let error = build_spec(&fields).expect_err("refused");
            assert!(error.0.contains(message), "{fields:?}: {error}");
        }
    }
}
