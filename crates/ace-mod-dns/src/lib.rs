//! The DNS module, a port of ace3's `FQDNAnalyzer` (`saq/modules/dns.py`) onto hickory-dns's
//! protocol library, hickory-proto.
//!
//! It asks for a domain name's A records and adds the first address as an ip observable. For a
//! name that is its own registrable domain it also asks for its MX records, and whether a name
//! under it that can't exist resolves, which means a wildcard record. Every outcome is a result
//! with a `status`: `ok`, `nxdomain` (the name doesn't exist), `no_answer` (it exists with no A
//! record) or `dns_error` (the resolver answered with a failure, such as SERVFAIL).
//!
//! A resolver that doesn't answer in time, or can't be reached, fails the task as unavailable, so
//! it runs again later (PLAN.md 1.20). ace3 records `dns_error` for that too.
//!
//! The queries go to the nameservers in the settings, or those in `/etc/resolv.conf`, as
//! dnspython's stub resolver asks them (`resolve`).

pub mod resolve;

use std::net::SocketAddr;
use std::time::Duration;

use ace_results::types::dns::FqdnAnalysis;
use ace_results::{NewObservable, ObservableKind, ResultEnvelope};
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, Resources, TaskContext};
use hickory_proto::rr::{Name, RData, RecordType};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::resolve::{Reply, ResolveError, aliases, name_of, resolve, to_text};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::lookup::<FqdnAnalyzer>();

/// The label of the name that can't exist, under a registrable domain. It is ace3's, constant so
/// a repeated lookup asks the same.
pub const WILDCARD_PROBE_LABEL: &str = "ace-wildcard-probe-nonexistent";

const STATUS_OK: &str = "ok";
const STATUS_NXDOMAIN: &str = "nxdomain";
const STATUS_NO_ANSWER: &str = "no_answer";
const STATUS_DNS_ERROR: &str = "dns_error";

/// The DNS module's settings.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct FqdnSettings {
    /// The resolvers to ask, each `host` or `host:port`, in order. Empty asks those in
    /// `/etc/resolv.conf`, as ace3 does.
    pub nameservers: Vec<String>,
    /// How long one lookup may take, over every try and every nameserver: ace3's
    /// `RESOLVER_TIMEOUT`, its resolver's `timeout` and `lifetime`.
    pub timeout_seconds: f64,
}

impl Default for FqdnSettings {
    fn default() -> Self {
        FqdnSettings {
            nameservers: Vec::new(),
            timeout_seconds: 5.0,
        }
    }
}

/// The DNS module.
pub struct FqdnAnalyzer {
    lifetime: Duration,
}

impl Module for FqdnAnalyzer {
    const NAME: &'static str = "fqdn_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        ..Resources::DEFAULT
    };
    type Output = FqdnAnalysis;
    type Settings = FqdnSettings;

    fn init(settings: &FqdnSettings) -> Result<Self, ModuleError> {
        let lifetime = Duration::try_from_secs_f64(settings.timeout_seconds)
            .ok()
            .filter(|t| !t.is_zero())
            .ok_or_else(|| ModuleError::other("timeout_seconds must be more than 0"))?;
        Ok(FqdnAnalyzer { lifetime })
    }
}

impl Lookup for FqdnAnalyzer {
    /// DNS over TCP, for an answer too long for a datagram. UDP isn't filtered.
    const TCP_PORTS: &'static [u16] = &[53];

    async fn analyze(
        &self,
        ctx: &TaskContext<FqdnSettings>,
    ) -> Result<Outcome<FqdnAnalysis>, ModuleError> {
        let fqdn = ctx.observable().value.clone();
        let nameservers = nameservers(&ctx.settings().nameservers).await?;
        let mut analysis = FqdnAnalysis::default();
        let mut result_observables = Vec::new();

        let name = match name_of(&fqdn) {
            Ok(name) => Some(name),
            Err(e) => {
                tracing::warn!("Problem resolving FQDN {fqdn}: {e}");
                analysis.status = Some(STATUS_DNS_ERROR.to_owned());
                None
            }
        };
        if let Some(name) = name {
            match self.lookup(&nameservers, &name, RecordType::A).await? {
                Ok(Reply::NxDomain) => analysis.status = Some(STATUS_NXDOMAIN.to_owned()),
                Ok(Reply::NoAnswer) => {
                    // the name exists with no A record: a domain with MX and no A is a mail-only
                    // domain, one with neither a shell
                    analysis.status = Some(STATUS_NO_ANSWER.to_owned());
                    self.analyze_apex(&mut analysis, &nameservers, &fqdn, &name)
                        .await?;
                }
                Ok(Reply::Records(records, response)) => {
                    analysis.status = Some(STATUS_OK.to_owned());
                    let mut addresses: Vec<String> = records
                        .iter()
                        .filter_map(|r| match r {
                            RData::A(a) => Some(a.0.to_string()),
                            _ => None,
                        })
                        .collect();
                    addresses.sort();
                    analysis.resolution_count = Some(addresses.len() as u64);
                    analysis.aliaslist = aliases(&response);
                    if let Some(first) = addresses.first() {
                        // only the first address, as ace3
                        analysis.ip_address = Some(first.clone());
                        result_observables.push(NewObservable::new(ObservableKind::Ip, first));
                    }
                    analysis.all_resolutions = addresses;
                    self.analyze_apex(&mut analysis, &nameservers, &fqdn, &name)
                        .await?;
                }
                Err(e) => {
                    tracing::warn!("Problem resolving FQDN {fqdn}: {e}");
                    analysis.status = Some(STATUS_DNS_ERROR.to_owned());
                }
            }
        }

        let summary = summary(&analysis);
        let mut result = ResultEnvelope::new(analysis);
        result.summary = summary;
        result.observables = result_observables;
        Ok(Outcome::Done(result))
    }
}

impl FqdnAnalyzer {
    /// A lookup whose resolver answered, or the task's failure when none could be reached.
    async fn lookup(
        &self,
        nameservers: &[SocketAddr],
        name: &Name,
        kind: RecordType,
    ) -> Result<Result<Reply, ResolveError>, ModuleError> {
        match resolve(nameservers, name, kind, self.lifetime).await {
            Err(e @ ResolveError::Unreachable(..)) => Err(ModuleError::Unavailable(e.into())),
            answered => Ok(answered),
        }
    }

    /// `_analyze_apex`: MX and the wildcard probe, only for a name that is its own registrable
    /// domain.
    async fn analyze_apex(
        &self,
        analysis: &mut FqdnAnalysis,
        nameservers: &[SocketAddr],
        fqdn: &str,
        name: &Name,
    ) -> Result<(), ModuleError> {
        let Some(apex) = ace_sdk::domains::top_domain_under_public_suffix(fqdn) else {
            return Ok(());
        };
        if fqdn.to_lowercase().trim_end_matches('.') != apex {
            return Ok(());
        }
        match self.lookup(nameservers, name, RecordType::MX).await? {
            Ok(Reply::Records(records, _)) => {
                let mut exchanges: Vec<String> = records
                    .iter()
                    .filter_map(|r| match r {
                        RData::MX(mx) => Some(to_text(&mx.exchange)),
                        _ => None,
                    })
                    .collect();
                exchanges.sort();
                analysis.mx = Some(exchanges);
            }
            Ok(Reply::NxDomain | Reply::NoAnswer) => analysis.mx = Some(Vec::new()),
            Err(e) => tracing::warn!("Problem resolving MX for {fqdn}: {e}"),
        }
        let probe = Name::from_labels([WILDCARD_PROBE_LABEL.as_bytes()])
            .and_then(|label| label.append_domain(name));
        match probe {
            Ok(probe) => match self.lookup(nameservers, &probe, RecordType::A).await? {
                // a name that can't exist resolving at all means a wildcard record
                Ok(Reply::Records(..)) => analysis.wildcard_dns = Some(true),
                Ok(Reply::NxDomain | Reply::NoAnswer) => analysis.wildcard_dns = Some(false),
                Err(e) => tracing::warn!("Problem probing {fqdn} for wildcard DNS: {e}"),
            },
            Err(e) => tracing::warn!("Problem probing {fqdn} for wildcard DNS: {e}"),
        }
        Ok(())
    }
}

/// The resolvers to ask: the settings', each looked up if it's a name, or `/etc/resolv.conf`'s.
async fn nameservers(configured: &[String]) -> Result<Vec<SocketAddr>, ModuleError> {
    let mut servers = Vec::new();
    if configured.is_empty() {
        let conf = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        servers.extend(resolv_conf_nameservers(&conf));
    }
    for entry in configured {
        if let Ok(ip) = entry.parse::<std::net::IpAddr>() {
            servers.push(SocketAddr::new(ip, 53));
            continue;
        }
        let address = if entry.contains(':') {
            entry.clone()
        } else {
            format!("{entry}:53")
        };
        let found = tokio::net::lookup_host(&address).await.map_err(|e| {
            ModuleError::Unavailable(format!("nameserver {entry} doesn't resolve: {e}").into())
        })?;
        servers.extend(found);
    }
    if servers.is_empty() {
        return Err(ModuleError::Unavailable(
            "no nameservers are configured".into(),
        ));
    }
    Ok(servers)
}

/// The `nameserver` lines of a resolv.conf, on port 53.
pub fn resolv_conf_nameservers(conf: &str) -> Vec<SocketAddr> {
    conf.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("nameserver")).then(|| words.next())?
        })
        .filter_map(|address| {
            // a scoped IPv6 address, such as fe80::1%eth0, isn't one the module can ask
            address
                .parse::<std::net::IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, 53))
        })
        .collect()
}

/// `format_item_list_for_summary`.
fn item_list(items: &[String]) -> String {
    let mut text = items
        .iter()
        .take(20)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if items.len() > 20 {
        text.push_str(&format!(" + {} more", items.len() - 20));
    }
    text
}

/// `FQDNAnalysis.generate_summary`.
fn summary(analysis: &FqdnAnalysis) -> Option<String> {
    let status = analysis.status.as_deref()?;
    match status {
        STATUS_NXDOMAIN => return Some("DNS Analysis: does not exist (nxdomain)".to_owned()),
        STATUS_DNS_ERROR => {
            return Some("DNS Analysis: lookup failed (no answer from any nameserver)".to_owned());
        }
        STATUS_NO_ANSWER => {
            let mut message = "DNS Analysis: exists but has no A record".to_owned();
            if let Some(mx) = analysis.mx.as_ref().filter(|mx| !mx.is_empty()) {
                message.push_str(&format!(", mx ({})", item_list(mx)));
            }
            return Some(message);
        }
        _ => {}
    }
    let mut message = "DNS Analysis:".to_owned();
    if !analysis.aliaslist.is_empty() {
        message.push_str(&format!(" aliaslist ({})", item_list(&analysis.aliaslist)));
    }
    if !analysis.all_resolutions.is_empty() {
        message.push_str(&format!(
            " ip addresses ({})",
            item_list(&analysis.all_resolutions)
        ));
    }
    match &analysis.mx {
        Some(mx) if !mx.is_empty() => message.push_str(&format!(" mx ({})", item_list(mx))),
        Some(_) => message.push_str(" no mx"),
        None => {}
    }
    if analysis.wildcard_dns == Some(true) {
        message.push_str(" WILDCARD DNS");
    }
    Some(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf_gives_its_nameservers_on_port_53() {
        let conf = "# comment\nsearch example.com\nnameserver 127.0.0.11\nnameserver ::1\n\
                    nameserver fe80::1%eth0\noptions ndots:0\n";
        assert_eq!(
            resolv_conf_nameservers(conf),
            [
                "127.0.0.11:53".parse::<SocketAddr>().expect("an address"),
                "[::1]:53".parse().expect("an address"),
            ]
        );
    }

    #[test]
    fn a_summary_of_more_than_twenty_items_counts_the_rest() {
        let analysis = FqdnAnalysis {
            status: Some(STATUS_OK.to_owned()),
            all_resolutions: (0..22).map(|i| format!("192.0.2.{i}")).collect(),
            ..FqdnAnalysis::default()
        };
        let text = summary(&analysis).expect("a summary");
        assert!(text.ends_with("192.0.2.19 + 2 more)"), "{text}");
        assert_eq!(summary(&FqdnAnalysis::default()), None);
    }
}
