//! `site_tagger`, a port of ace3's `SiteTagAnalyzer` (`saq/modules/tag.py`).
//!
//! A site lists tag rules in a CSV file, `data/etc/site_tags.csv` in ace3, one rule a row:
//!
//! ```text
//! o_types,match_type,ignore_case,value,tags
//! fqdn|url,subdomain,false,corp.example,internal|corp
//! ```
//!
//! `o_types` and `tags` are separated by `|`; `match_type` is `default` (the whole value), `glob`
//! (Python's `fnmatch.fnmatchcase`), `regex` (found anywhere in the value), `cidr` (an IP address in the
//! network) or `subdomain` (the value is the domain or below it); `ignore_case` is true for `true`,
//! `yes` or `1`, ignoring case and surrounding space. An observable of a listed type gets the tags of
//! every row that matches it, in the rows' order, and a result only when one does.
//!
//! The file is the module's `csv` setting here, its text as it is, in the site's overlay: a pool's
//! container has no site directory to watch, and the overlay is the site's. ace3 reloads the file
//! when it changes; ace4 reads the overlay when the pool starts. A row ace3 can't load is logged and
//! skipped, as in ace3: one without five fields, an unknown match type, a regex that doesn't compile
//! and a CIDR that isn't a network. ace3 compiles a regex with Python's `re`; here it's the `regex`
//! crate, so a pattern using what only `re` has, such as a look-around or a backreference, is
//! skipped, with the reason in the log.
//!
//! ace3 enables the module, and needs `data/etc/site_tags.csv`, which it doesn't ship: without the
//! file the module doesn't load. Here it's off until the site's overlay gives it a section, as for a
//! module ace3 ships disabled, since with no rows it would only start a task on every observable to
//! find nothing.

use std::collections::BTreeMap;
use std::time::Duration;

use ace_pycompat::ipaddress::{IpAddress, ip_address, ipv4_address, ipv6_address};
use ace_results::types::tag::SiteTagAnalysis;
use ace_results::{ObservableKind, ResultEnvelope};
use ace_sdk::takes::{Condition, Takes};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use regex::{Regex, RegexBuilder};
use schemars::JsonSchema;
use serde::Deserialize;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<SiteTagger>();

/// What one pattern may compile to, as the analyst-edited lists allow (`ace_sdk::lists`).
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// The module's settings, ace3's `analysis_module_site_tagger` section.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct SiteTaggerSettings {
    /// The text of the site's tag CSV, ace3's `csv_file`.
    pub csv: String,
}

/// How a row matches a value.
#[derive(Debug)]
enum Matcher {
    /// The whole value, lowercased first when the row ignores case.
    Default(String),
    /// A glob, already translated, matched against the value lowercased when the row ignores case.
    /// None when the translation doesn't compile, which matches nothing, as `fnmatch` would raise.
    Glob(Option<Regex>),
    Regex(Regex),
    Cidr(Network),
    /// The value is this domain or below it.
    Subdomain(String),
}

/// One row of the CSV.
#[derive(Debug)]
struct Rule {
    matcher: Matcher,
    ignore_case: bool,
    tags: Vec<String>,
}

/// An IP network, as `ipaddress.ip_network(value)` makes one with `strict` on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Network {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl Network {
    /// `ipaddress.ip_network(value)`: an IPv4 network, else an IPv6 one, refusing one with host bits
    /// set. The prefix is decimal digits; an IPv4 network may give a netmask or a host mask instead.
    fn parse(value: &str) -> Result<Network, String> {
        let parts: Vec<&str> = value.split('/').collect();
        let (address, prefix) = match parts.as_slice() {
            [address] => (*address, None),
            [address, prefix] => (*address, Some(*prefix)),
            _ => {
                return Err(format!(
                    "{value:?} does not appear to be an IPv4 or IPv6 network"
                ));
            }
        };
        if let Ok(v4) = ipv4_address(address) {
            let mask = match prefix {
                None => u32::MAX,
                Some(prefix) => {
                    v4_mask(prefix).ok_or_else(|| format!("invalid netmask {prefix:?}"))?
                }
            };
            if v4.ip & mask != v4.ip {
                return Err(format!("{value} has host bits set"));
            }
            return Ok(Network::V4 {
                network: v4.ip,
                mask,
            });
        }
        if let Ok(v6) = ipv6_address(address) {
            let mask = match prefix {
                None => u128::MAX,
                Some(prefix) => {
                    let bits = prefix_length(prefix, 128)
                        .ok_or_else(|| format!("invalid prefix length {prefix:?}"))?;
                    u128::MAX.checked_shl(128 - bits).unwrap_or(0)
                }
            };
            if v6.ip & mask != v6.ip {
                return Err(format!("{value} has host bits set"));
            }
            return Ok(Network::V6 {
                network: v6.ip,
                mask,
            });
        }
        Err(format!(
            "{value:?} does not appear to be an IPv4 or IPv6 network"
        ))
    }

    /// `ipaddress.ip_address(value) in network`: False for an address of the other version.
    fn contains(&self, address: &IpAddress) -> bool {
        match (self, address) {
            (Network::V4 { network, mask }, IpAddress::V4(a)) => a.ip & mask == *network,
            (Network::V6 { network, mask }, IpAddress::V6(a)) => a.ip & mask == *network,
            _ => false,
        }
    }
}

/// A prefix length of ASCII digits, at most `max`.
fn prefix_length(text: &str, max: u32) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u32>().ok().filter(|bits| *bits <= max)
}

/// An IPv4 prefix: a length, a netmask such as `255.255.255.0`, or a host mask such as
/// `0.0.0.255`, as `IPv4Network._make_netmask` takes them.
fn v4_mask(text: &str) -> Option<u32> {
    let from_length = |bits: u32| u32::MAX.checked_shl(32 - bits).unwrap_or(0);
    if let Some(bits) = prefix_length(text, 32) {
        return Some(from_length(bits));
    }
    let ip = ipv4_address(text).ok()?.ip;
    // a netmask is ones then zeros, a host mask zeros then ones
    let as_netmask = |ip: u32| (ip.leading_ones() + ip.trailing_zeros() == 32).then_some(ip);
    as_netmask(ip).or_else(|| as_netmask(!ip))
}

/// ace3's `is_subdomain(src, dst)`: whether `value` is `domain` or below it, label by label from the
/// right, ignoring case.
fn is_subdomain(value: &str, domain: &str) -> bool {
    let value = value.to_lowercase();
    let domain = domain.to_lowercase();
    let mut value = value.split('.').rev();
    domain
        .split('.')
        .rev()
        .all(|label| value.next() == Some(label))
}

impl Rule {
    /// ace3's `_tag_mapping(match_type, ignore_case, value, tags)`, or why the row is skipped.
    fn new(match_type: &str, ignore_case: bool, value: &str, tags: &str) -> Result<Rule, String> {
        let matcher = match match_type {
            "default" => Matcher::Default(if ignore_case {
                value.to_lowercase()
            } else {
                value.to_owned()
            }),
            "glob" => {
                let pattern = if ignore_case {
                    value.to_lowercase()
                } else {
                    value.to_owned()
                };
                Matcher::Glob(Regex::new(&ace_pycompat::fnmatch::translate(&pattern)).ok())
            }
            "regex" => Matcher::Regex(
                RegexBuilder::new(value)
                    .case_insensitive(ignore_case)
                    .size_limit(REGEX_SIZE_LIMIT)
                    .dfa_size_limit(REGEX_SIZE_LIMIT)
                    .build()
                    .map_err(|e| format!("the regex doesn't compile: {e}"))?,
            ),
            "cidr" => Matcher::Cidr(Network::parse(value)?),
            "subdomain" => Matcher::Subdomain(value.to_owned()),
            other => return Err(format!("invalid match type: {other}")),
        };
        Ok(Rule {
            matcher,
            ignore_case,
            tags: tags.split('|').map(str::to_owned).collect(),
        })
    }

    fn matches(&self, value: &str) -> bool {
        match &self.matcher {
            Matcher::Default(wanted) => {
                if self.ignore_case {
                    value.to_lowercase() == *wanted
                } else {
                    value == wanted
                }
            }
            Matcher::Glob(glob) => glob.as_ref().is_some_and(|glob| {
                if self.ignore_case {
                    glob.is_match(&value.to_lowercase())
                } else {
                    glob.is_match(value)
                }
            }),
            Matcher::Regex(regex) => regex.is_match(value),
            Matcher::Cidr(network) => ip_address(value).is_ok_and(|a| network.contains(&a)),
            Matcher::Subdomain(domain) => is_subdomain(value, domain),
        }
    }
}

/// The rows of the CSV by observable type, in the file's order, as ace3's `load_csv_file` loads them.
/// Whether `load` logs the rows it can't read: once, where the module is built, and not again for
/// its declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Report {
    Errors,
    Quiet,
}

fn load(csv: &str, report: Report) -> BTreeMap<String, Vec<std::sync::Arc<Rule>>> {
    // ace3 opens the file in text mode, which reads `\r\n` and `\r` as `\n`
    let text = csv.replace("\r\n", "\n").replace('\r', "\n");
    let mut rules: BTreeMap<String, Vec<std::sync::Arc<Rule>>> = BTreeMap::new();
    for row in ace_pycompat::csv::reader(&text) {
        let row = match row {
            Ok(row) => row,
            // ace3's reader raises out of the load, keeping the rows before it
            Err(e) => {
                if report == Report::Errors {
                    tracing::error!("the site tags CSV stops at an error: {}", e.message);
                }
                break;
            }
        };
        if row.is_empty() {
            continue;
        }
        let rule = match row.as_slice() {
            [o_types, match_type, ignore_case, value, tags] => {
                let ignore_case = matches!(
                    ignore_case.trim().to_lowercase().as_str(),
                    "true" | "yes" | "1"
                );
                Rule::new(match_type, ignore_case, value, tags).map(|r| (o_types, r))
            }
            _ => Err(format!("expected 5 fields, got {}", row.len())),
        };
        match rule {
            Ok((o_types, rule)) => {
                let rule = std::sync::Arc::new(rule);
                for o_type in o_types.split('|') {
                    rules
                        .entry(o_type.to_owned())
                        .or_default()
                        .push(rule.clone());
                }
            }
            Err(e) if report == Report::Errors => {
                tracing::error!("invalid tag specification {}: {e}", row.join(","));
            }
            Err(_) => {}
        }
    }
    rules
}

/// The site tagger.
pub struct SiteTagger {
    rules: BTreeMap<String, Vec<std::sync::Arc<Rule>>>,
}

impl SiteTagger {
    /// The tags of every row that matches an observable of type `kind` with `value`, in order.
    pub fn tags_for(&self, kind: &str, value: &str) -> Vec<String> {
        self.rules
            .get(kind)
            .into_iter()
            .flatten()
            .filter(|rule| rule.matches(value))
            .flat_map(|rule| rule.tags.iter().cloned())
            .collect()
    }
}

impl Module for SiteTagger {
    const NAME: &'static str = "site_tagger";
    // ace3's valid_observable_types is None: every type
    const INPUTS: &'static [ObservableKind] = ObservableKind::BUILTIN;
    const ENABLED_BY_DEFAULT: bool = false;
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(30),
        ..Resources::DEFAULT
    };
    type Output = SiteTagAnalysis;
    type Settings = SiteTaggerSettings;

    fn init(settings: &SiteTaggerSettings) -> Result<Self, ModuleError> {
        Ok(SiteTagger {
            rules: load(&settings.csv, Report::Errors),
        })
    }

    fn takes(settings: &SiteTaggerSettings) -> Takes {
        // the types the rows are for, read as `init` reads them; a type this binary hasn't is no
        // observable's
        let kinds = load(&settings.csv, Report::Quiet)
            .keys()
            .filter_map(|kind| kind.parse().ok())
            .collect();
        Takes::everything().and(Condition::Kind(kinds), "no site tag row is for its type")
    }
}

impl Parser for SiteTagger {
    fn analyze(
        &self,
        ctx: &TaskContext<SiteTaggerSettings>,
    ) -> Result<Outcome<SiteTagAnalysis>, ModuleError> {
        let observable = ctx.observable();
        let kind = observable.kind.as_str();
        let tags = self.tags_for(kind, &observable.value);
        if tags.is_empty() {
            return Ok(Outcome::Skipped("no site tag row matches".to_owned()));
        }
        let mut result = ResultEnvelope::new(SiteTagAnalysis {
            tags_added: tags.clone(),
        });
        result.summary = Some(format!("Site Tags: {}", tags.join(", ")));
        for tag in tags {
            if !result.analyzed.tags.contains(&tag) {
                result.analyzed.tags.push(tag);
            }
        }
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tagger(csv: &str) -> SiteTagger {
        SiteTagger::init(&SiteTaggerSettings {
            csv: csv.to_owned(),
        })
        .expect("builds")
    }

    #[test]
    fn each_match_type_matches_as_ace3_s() {
        let t = tagger(
            "fqdn,default,false,Exact.Example,exact\n\
             fqdn,default,yes,CASE.example,case\n\
             url,glob,false,http://*.example/[!x]*,glob\n\
             url,glob,TRUE,HTTP://SHOUT.*,shout\n\
             email_address,regex,1,^admin@,admin\n\
             ipv4|ip,cidr,false,10.0.0.0/8,internal\n\
             ip,cidr,false,192.168.1.0/255.255.255.0,lan\n\
             ip,cidr,false,2001:db8::/32,doc6\n\
             fqdn,subdomain,false,corp.example,corp|internal\n",
        );
        assert_eq!(t.tags_for("fqdn", "Exact.Example"), ["exact"]);
        assert!(t.tags_for("fqdn", "exact.example").is_empty());
        assert_eq!(t.tags_for("fqdn", "case.EXAMPLE"), ["case"]);
        assert_eq!(t.tags_for("url", "http://a.example/path"), ["glob"]);
        assert!(t.tags_for("url", "http://a.example/xpath").is_empty());
        assert_eq!(t.tags_for("url", "http://shout.example/"), ["shout"]);
        assert_eq!(t.tags_for("email_address", "ADMIN@corp.example"), ["admin"]);
        assert_eq!(t.tags_for("ip", "10.1.2.3"), ["internal"]);
        assert_eq!(t.tags_for("ipv4", "10.1.2.3"), ["internal"]);
        assert_eq!(t.tags_for("ip", "192.168.1.7"), ["lan"]);
        assert_eq!(t.tags_for("ip", "2001:db8::1"), ["doc6"]);
        assert!(t.tags_for("ip", "not an address").is_empty());
        assert!(t.tags_for("ip", "010.1.2.3").is_empty());
        assert_eq!(t.tags_for("fqdn", "a.b.CORP.example"), ["corp", "internal"]);
        assert_eq!(t.tags_for("fqdn", "corp.example"), ["corp", "internal"]);
        assert!(t.tags_for("fqdn", "notcorp.example").is_empty());
        assert!(t.tags_for("fqdn", "example").is_empty());
    }

    #[test]
    fn a_row_ace3_can_t_load_is_skipped_and_the_rest_are_kept() {
        let t = tagger(
            "fqdn,default,false,a.example\n\
             fqdn,nonsense,false,a.example,bad\n\
             fqdn,regex,false,(?<=x)y,lookbehind\n\
             ip,cidr,false,10.0.0.1/8,host_bits\n\
             ip,cidr,false,10.0.0.0/33,too_long\n\
             \n\
             fqdn,default,false,a.example,kept|again\n\
             fqdn,default,false,a.example,kept\n",
        );
        assert_eq!(t.tags_for("fqdn", "a.example"), ["kept", "again", "kept"]);
        assert!(t.tags_for("ip", "10.0.0.1").is_empty());
    }

    #[test]
    fn quoted_fields_and_line_endings_read_as_python_s_csv_module_reads_them() {
        let t = tagger("\"fqdn|url\",default,false,\"a,b\",\"x|y\"\r\nfqdn,default,false,c,z\r");
        assert_eq!(t.tags_for("fqdn", "a,b"), ["x", "y"]);
        assert_eq!(t.tags_for("url", "a,b"), ["x", "y"]);
        assert_eq!(t.tags_for("fqdn", "c"), ["z"]);
    }

    #[test]
    fn networks_parse_as_ip_network_does() {
        assert_eq!(
            Network::parse("10.0.0.0/8"),
            Ok(Network::V4 {
                network: 0x0a00_0000,
                mask: 0xff00_0000
            })
        );
        assert_eq!(
            Network::parse("10.0.0.0/0.255.255.255"),
            Ok(Network::V4 {
                network: 0x0a00_0000,
                mask: 0xff00_0000
            })
        );
        assert!(Network::parse("10.0.0.0/255.0.255.0").is_err());
        assert!(Network::parse("10.0.0.0/+8").is_err());
        assert!(Network::parse("10.0.0.0/8/8").is_err());
        assert!(Network::parse("::1/129").is_err());
        assert!(Network::parse("1.2.3.4").is_ok());
        assert!(Network::parse("0.0.0.0/0").is_ok());
        assert!(Network::parse("::/0").is_ok());
    }
}
