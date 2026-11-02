//! IANA's RDAP bootstrap registries: which RDAP server answers for a TLD or an IP network
//! (RFC 9224). whoisit loads them once per process; the module keeps them for a while and then
//! fetches them again.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use ace_sdk::http::{HttpClient, HttpError, check_status};
use icann_rdap_common::iana::{RdapBootstrapRegistry, get_preferred_url};
use ipnet::IpNet;
use tokio::sync::Mutex;

/// The registries a lookup needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Dns,
    Ipv4,
    Ipv6,
}

impl Kind {
    fn file(self) -> &'static str {
        match self {
            Kind::Dns => "dns.json",
            Kind::Ipv4 => "ipv4.json",
            Kind::Ipv6 => "ipv6.json",
        }
    }
}

/// One registry's services: what each serves, and its base URLs.
#[derive(Debug, Clone)]
pub struct Registry {
    services: Vec<(Vec<String>, Vec<String>)>,
}

impl Registry {
    fn new(registry: RdapBootstrapRegistry) -> Self {
        Registry {
            services: registry
                .services
                .into_iter()
                .filter_map(|service| {
                    let mut parts = service.into_iter();
                    let entries = parts.next()?;
                    let urls = parts.next_back()?;
                    Some((entries, urls))
                })
                .collect(),
        }
    }

    /// The base URLs for a TLD, or for a domain's last two labels (whoisit tries those
    /// first).
    pub fn for_tld(&self, tld: &str) -> Option<&[String]> {
        let tld = tld.to_lowercase();
        self.services
            .iter()
            .find(|(tlds, _)| tlds.iter().any(|t| t.to_lowercase() == tld))
            .map(|(_, urls)| urls.as_slice())
    }

    /// The base URLs for the first network in the registry that holds `ip`.
    pub fn for_ip(&self, ip: IpAddr) -> Option<&[String]> {
        self.services
            .iter()
            .find(|(nets, _)| {
                nets.iter()
                    .filter_map(|n| n.parse::<IpNet>().ok())
                    .any(|net| net.contains(&ip))
            })
            .map(|(_, urls)| urls.as_slice())
    }
}

/// The preferred base URL among a service's: the first HTTPS one, else the first.
pub fn preferred(urls: &[String]) -> Option<String> {
    get_preferred_url(urls.to_vec()).ok()
}

/// The registries, fetched when first needed and again after `ttl`.
pub struct Bootstrap {
    base_url: String,
    ttl: Duration,
    cache: Mutex<Vec<(Kind, Instant, Registry)>>,
}

impl Bootstrap {
    pub fn new(base_url: &str, ttl: Duration) -> Self {
        let mut base_url = base_url.to_owned();
        if !base_url.ends_with('/') {
            base_url.push('/');
        }
        Bootstrap {
            base_url,
            ttl,
            cache: Mutex::new(Vec::new()),
        }
    }

    /// The registry of `kind`, from the cache or fetched.
    pub async fn registry(
        &self,
        client: &HttpClient,
        kind: Kind,
    ) -> Result<Registry, BootstrapError> {
        let mut cache = self.cache.lock().await;
        cache.retain(|(_, fetched, _)| fetched.elapsed() < self.ttl);
        if let Some((_, _, registry)) = cache.iter().find(|(k, _, _)| *k == kind) {
            return Ok(registry.clone());
        }
        let url = format!("{}{}", self.base_url, kind.file());
        let response = client
            .send(client.get(&url).header("Accept", "application/json"))
            .await
            .and_then(check_status)
            .map_err(BootstrapError::Http)?;
        let registry: RdapBootstrapRegistry = response
            .json()
            .await
            .map_err(|e| BootstrapError::Http(HttpError::from_reqwest(e)))?;
        let registry = Registry::new(registry);
        cache.push((kind, Instant::now(), registry.clone()));
        Ok(registry)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("{0}")]
    Http(HttpError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry(json: &str) -> Registry {
        Registry::new(serde_json::from_str(json).expect("a registry"))
    }

    #[test]
    fn tlds_and_networks_find_their_servers() {
        let dns = registry(
            r#"{"version":"1.0","publication":"x","services":[
                [["com","net"],["https://rdap.verisign.com/com/v1/"]],
                [["uk"],["http://rdap.nominet.uk/uk/","https://rdap.nominet.uk/uk/"]]]}"#,
        );
        assert_eq!(
            dns.for_tld("COM"),
            Some(&["https://rdap.verisign.com/com/v1/".to_owned()][..])
        );
        assert_eq!(dns.for_tld("org"), None);
        assert_eq!(
            preferred(dns.for_tld("uk").expect("listed")).as_deref(),
            Some("https://rdap.nominet.uk/uk/")
        );
        let ipv4 = registry(
            r#"{"version":"1.0","publication":"x","services":[
                [["8.0.0.0/8"],["https://rdap.arin.net/registry/","http://rdap.arin.net/registry/"]]]}"#,
        );
        assert!(
            ipv4.for_ip("8.8.8.8".parse().expect("an address"))
                .is_some()
        );
        assert!(
            ipv4.for_ip("9.9.9.9".parse().expect("an address"))
                .is_none()
        );
    }
}
