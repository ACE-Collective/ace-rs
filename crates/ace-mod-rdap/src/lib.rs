//! The RDAP module, a port of ace3's `RdapAnalyzer` (`saq/modules/rdap.py`) onto ICANN's RDAP
//! library, icann-rdap-common.
//!
//! For a domain it asks the registry's RDAP server about the registrable domain (eTLD+1), and
//! follows a `related` link to the registrar's server as whoisit does; for a public IP address,
//! the regional registry about the network that holds it. IANA's bootstrap registries say which
//! server to ask. Requests go through the SDK's HTTP client.
//!
//! ICANN's client crate, icann-rdap-client, builds its own reqwest client with native-tls and a
//! vendored OpenSSL, so the module uses the library's data model and bootstrap types and makes
//! its requests through `ace_sdk::http::HttpClient`, which verifies certificates with rustls.
//!
//! ace3 falls back to WHOIS when RDAP can't answer. That isn't ported: the module records RDAP's
//! error instead.

mod bootstrap;
mod parse;

use std::net::IpAddr;
use std::time::Duration;

use ace_results::ObservableKind;
use ace_results::ResultEnvelope;
use ace_results::types::rdap::RdapAnalysis;
use ace_sdk::http::{HttpClient, HttpErrorKind, check_status};
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, Resources, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use crate::bootstrap::{Bootstrap, BootstrapError, Kind};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::lookup::<RdapAnalyzer>();

/// At most this many email addresses are kept, as in ace3.
const MAX_EMAILS: usize = 20;

/// The RDAP module's settings.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct RdapSettings {
    /// Where IANA's bootstrap registries (`dns.json`, `ipv4.json`, `ipv6.json`) are.
    pub bootstrap_url: String,
    /// How long a bootstrap registry is used before it is fetched again.
    pub bootstrap_ttl_seconds: u64,
    /// The timeout of each HTTP request.
    pub request_timeout_seconds: u64,
}

impl Default for RdapSettings {
    fn default() -> Self {
        RdapSettings {
            bootstrap_url: "https://data.iana.org/rdap/".to_owned(),
            bootstrap_ttl_seconds: 24 * 3600,
            request_timeout_seconds: 30,
        }
    }
}

/// The RDAP module.
pub struct RdapAnalyzer {
    client: HttpClient,
    bootstrap: Bootstrap,
}

impl Module for RdapAnalyzer {
    const NAME: &'static str = "rdap_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn, ObservableKind::Ip];
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(120),
        ..Resources::DEFAULT
    };
    type Output = RdapAnalysis;
    type Settings = RdapSettings;

    fn init(settings: &RdapSettings) -> Result<Self, ModuleError> {
        let client = HttpClient::builder()
            .timeout(Duration::from_secs(settings.request_timeout_seconds))
            .build()
            .map_err(ModuleError::other)?;
        Ok(RdapAnalyzer {
            client,
            bootstrap: Bootstrap::new(
                &settings.bootstrap_url,
                Duration::from_secs(settings.bootstrap_ttl_seconds),
            ),
        })
    }
}

impl Lookup for RdapAnalyzer {
    const TCP_PORTS: &'static [u16] = &[443];

    async fn analyze(
        &self,
        ctx: &TaskContext<RdapSettings>,
    ) -> Result<Outcome<RdapAnalysis>, ModuleError> {
        let observable = ctx.observable();
        let ip: Option<IpAddr> = observable
            .kind
            .is_subtype_of(ObservableKind::Ip)
            .then(|| observable.value.trim().parse().ok())
            .flatten();
        // a private or reserved address has no public registration data (custom_requirement)
        if let Some(ip) = ip
            && !ace_sdk::ip::is_global(ip)
        {
            return Ok(Outcome::Skipped(format!("{ip} isn't globally routable")));
        }

        let now = ctx.now();
        let mut analysis = RdapAnalysis {
            datetime_of_analysis: Some(parse::isoformat_utc(now)),
            ..RdapAnalysis::default()
        };
        // IP addresses are asked about as they are; a domain as its registrable domain
        let target = match (&ip, observable.kind.is_subtype_of(ObservableKind::Ip)) {
            (_, true) => observable.value.trim().to_owned(),
            (_, false) => ace_sdk::domains::registrable_domain(&observable.value),
        };

        match self.try_rdap(&target, ip, &mut analysis, now).await? {
            Attempt::Done => analysis.lookup_protocol = Some("rdap".to_owned()),
            Attempt::NotFound => {}
            Attempt::Failed(error) => {
                // ace3 tries WHOIS here, which isn't ported
                analysis.error = Some(format!("rdap: {error}"));
                analysis.rdap_attempt_error = Some(error);
            }
        }
        let summary = summary(&analysis);
        let mut result = ResultEnvelope::new(analysis);
        result.summary = summary;
        Ok(Outcome::Done(result))
    }
}

/// How an RDAP attempt went.
enum Attempt {
    Done,
    /// The registry said the domain doesn't exist; `analysis.error` says so.
    NotFound,
    /// RDAP couldn't answer, for this reason.
    Failed(String),
}

/// The first line of an error, as ace3 records it.
fn first_line(text: &str) -> String {
    text.split('\n')
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

impl RdapAnalyzer {
    async fn try_rdap(
        &self,
        target: &str,
        ip: Option<IpAddr>,
        analysis: &mut RdapAnalysis,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Attempt, ModuleError> {
        let kind = match ip {
            Some(IpAddr::V4(_)) => Kind::Ipv4,
            Some(IpAddr::V6(_)) => Kind::Ipv6,
            None => Kind::Dns,
        };
        let registry = match self.bootstrap.registry(&self.client, kind).await {
            Ok(registry) => registry,
            Err(BootstrapError::Http(e)) if e.is_unavailable() => return Err(e.into()),
            Err(e) => {
                return Ok(Attempt::Failed(first_line(&format!(
                    "bootstrap failed: {e}"
                ))));
            }
        };

        let (urls, what) = match ip {
            Some(ip) => (registry.for_ip(ip), "ip"),
            None => {
                let labels: Vec<&str> = target.split('.').collect();
                if labels.len() < 2 {
                    return Ok(Attempt::Failed(format!(
                        "Failed to extract TLD from domain \"{target}\""
                    )));
                }
                // whoisit tries the last two labels before the TLD
                let sld = labels[labels.len() - 2..].join(".");
                let tld = labels[labels.len() - 1];
                (
                    registry.for_tld(&sld).or_else(|| registry.for_tld(tld)),
                    "domain",
                )
            }
        };
        let Some(base) = urls.and_then(bootstrap::preferred) else {
            let thing = if ip.is_some() { "address" } else { "TLD" };
            return Ok(Attempt::Failed(format!(
                "no RDAP service for {thing}: {target} has no known RDAP endpoint"
            )));
        };
        let base = if base.ends_with('/') {
            base
        } else {
            format!("{base}/")
        };
        let url = format!("{base}{what}/{target}");

        let mut raw = match self.get(&url).await? {
            Fetched::Json(raw) => raw,
            Fetched::NotFound => {
                let message = format!(
                    "RDAP GET request to {url} returned a 404 error, the resource does not exist"
                );
                let mut error = first_line(&format!("rdap: domain not found: {message}"));
                error.truncate(
                    error
                        .char_indices()
                        .nth(200)
                        .map_or(error.len(), |(i, _)| i),
                );
                analysis.error = Some(error);
                return Ok(Attempt::NotFound);
            }
            Fetched::Error(error) => return Ok(Attempt::Failed(first_line(&error))),
        };

        if ip.is_none() {
            // overlay the registrar's answer over the registry's, as whoisit's follow_related
            if let Some(related) = related_link(&raw) {
                match self.get(&related).await {
                    Ok(Fetched::Json(more)) => merge(&mut raw, more),
                    Ok(_) | Err(_) => tracing::warn!("the related RDAP query failed"),
                }
            }
        }

        let parsed = match parse::parse(&raw, ip) {
            Ok(parsed) => parsed,
            Err(e) => {
                return Ok(Attempt::Failed(first_line(&format!(
                    "rdap client error: {e}"
                ))));
            }
        };
        analysis.rdap_raw_json = Some(raw.to_string());
        analysis.domain_name = Some(if parsed.name.is_empty() {
            target.to_owned()
        } else {
            parsed.name.clone()
        });
        analysis.registrar = parsed.registrar;
        analysis.name_servers = Some(parsed.nameservers);
        let mut emails = parsed.emails;
        emails.sort();
        emails.truncate(MAX_EMAILS);
        analysis.emails = Some(emails);
        // ace3 falls back to the bootstrap's name for the registry when there is no self link
        analysis.rdap_service_url = Some(parsed.url).filter(|u| !u.is_empty());
        if ip.is_some() {
            analysis.network_cidr = parsed.network;
            analysis.network_name = Some(parsed.name).filter(|n| !n.is_empty());
            analysis.country = Some(parsed.country).filter(|c| !c.is_empty());
            analysis.ip_version = parsed.ip_version;
            analysis.assignment_type = Some(parsed.assignment_type).filter(|t| !t.is_empty());
        }
        if let Some(created) = parsed.registration {
            analysis.datetime_created = Some(created.isoformat());
            analysis.age_created_in_days = Some(created.age_in_days(now));
        }
        if let Some(updated) = parsed.last_changed {
            analysis.datetime_of_last_update = Some(updated.isoformat());
            analysis.age_last_updated_in_days = Some(updated.age_in_days(now));
        }
        if let Some(expires) = parsed.expiration {
            analysis.datetime_expiration = Some(expires.isoformat());
        }
        Ok(Attempt::Done)
    }

    /// A GET that answers with JSON. A peer that can't be reached fails the task, so it runs
    /// again later.
    async fn get(&self, url: &str) -> Result<Fetched, ModuleError> {
        let request = self
            .client
            .get(url)
            .header("Accept", "application/rdap+json, application/json");
        let response = match self.client.send(request).await {
            Ok(response) => response,
            Err(e) if e.is_unavailable() => return Err(e.into()),
            Err(e) => return Ok(Fetched::Error(format!("rdap client error: {e}"))),
        };
        let status = response.status();
        let response = match check_status(response) {
            Ok(response) => response,
            Err(e) if e.is_unavailable() => return Err(e.into()),
            Err(e) if e.kind() == HttpErrorKind::Status(reqwest::StatusCode::NOT_FOUND) => {
                return Ok(Fetched::NotFound);
            }
            Err(_) => {
                // whoisit's messages for the statuses it names
                let what = match status.as_u16() {
                    401 => "a 401 error, unauthorized".to_owned(),
                    403 => "a 403 error, forbidden".to_owned(),
                    422 => "a 422 error, the request was unprocessable".to_owned(),
                    500 => "a 500 error, the resource returned a remote server error".to_owned(),
                    code => format!("a non-200 status code of {code}"),
                };
                return Ok(Fetched::Error(format!(
                    "RDAP GET request to {url} returned {what}"
                )));
            }
        };
        match response.json::<Value>().await {
            Ok(raw) => Ok(Fetched::Json(raw)),
            Err(e) => Ok(Fetched::Error(format!(
                "Failed to parse RDAP Query response as JSON: {e}"
            ))),
        }
    }
}

enum Fetched {
    Json(Value),
    NotFound,
    Error(String),
}

/// The first `related` or `registration` link that isn't a web page.
fn related_link(raw: &Value) -> Option<String> {
    raw["links"].as_array()?.iter().find_map(|link| {
        let rel = link["rel"].as_str().unwrap_or_default();
        let href = link["href"].as_str().unwrap_or_default();
        let kind = link["type"].as_str().unwrap_or_default();
        (matches!(rel, "related" | "registration")
            && !href.is_empty()
            && !kind.starts_with("text/html"))
        .then(|| href.to_owned())
    })
}

/// whoisit's `recursive_merge`: objects merge key by key, `events` lists merge by
/// `eventAction` and `notices` and `remarks` by `title`, and anything else is replaced.
fn merge(into: &mut Value, from: Value) {
    let (Value::Object(into), Value::Object(from)) = (into, from) else {
        return;
    };
    for (key, value) in from {
        match (into.get_mut(&key), value) {
            (Some(existing @ Value::Object(_)), value @ Value::Object(_)) => merge(existing, value),
            (existing, Value::Array(list)) if key == "events" => {
                let base = existing
                    .and_then(|e| e.as_array().cloned())
                    .unwrap_or_default();
                into.insert(key, Value::Array(merge_lists(base, list, "eventAction")));
            }
            (existing, Value::Array(list)) if key == "notices" || key == "remarks" => {
                let base = existing
                    .and_then(|e| e.as_array().cloned())
                    .unwrap_or_default();
                into.insert(key, Value::Array(merge_lists(base, list, "title")));
            }
            (_, value) => {
                into.insert(key, value);
            }
        }
    }
}

/// whoisit's `recursive_merge_lists`: entries without the key are dropped.
fn merge_lists(base: Vec<Value>, more: Vec<Value>, key: &str) -> Vec<Value> {
    let keyed = |list: Vec<Value>| -> Vec<(String, Value)> {
        let mut out: Vec<(String, Value)> = Vec::new();
        for item in list {
            let Some(name) = item.get(key).map(|k| k.to_string()) else {
                continue;
            };
            match out.iter_mut().find(|(n, _)| *n == name) {
                Some(slot) => slot.1 = item,
                None => out.push((name, item)),
            }
        }
        out
    };
    let mut merged = keyed(base);
    for (name, item) in keyed(more) {
        match merged.iter_mut().find(|(n, _)| *n == name) {
            Some((_, existing)) if existing.is_object() && item.is_object() => {
                merge(existing, item)
            }
            Some(slot) => slot.1 = item,
            None => merged.push((name, item)),
        }
    }
    merged.into_iter().map(|(_, item)| item).collect()
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

/// `RdapAnalysis.generate_summary`.
fn summary(analysis: &RdapAnalysis) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(error) = &analysis.error {
        parts.push(format!("error: {error}"));
    } else {
        if let Some(cidr) = &analysis.network_cidr {
            match &analysis.network_name {
                Some(name) => parts.push(format!("network: {cidr} ({name})")),
                None => parts.push(format!("network: {cidr}")),
            }
        }
        if let Some(country) = &analysis.country {
            parts.push(format!("country: {country}"));
        }
        if let Some(age) = &analysis.age_created_in_days {
            parts.push(format!("created: {age} day(s) ago"));
        }
        if let Some(age) = &analysis.age_last_updated_in_days {
            parts.push(format!("last updated: {age} day(s) ago"));
        }
        if let Some(servers) = analysis.name_servers.as_ref().filter(|s| !s.is_empty()) {
            parts.push(format!("nameservers: ({})", item_list(servers)));
        }
        if let Some(registrar) = &analysis.registrar {
            parts.push(format!("registrar: {registrar}"));
        }
        if let Some(url) = &analysis.rdap_service_url {
            parts.push(format!("rdap service: {url}"));
        }
        if let Some(emails) = analysis.emails.as_ref().filter(|e| !e.is_empty()) {
            parts.push(format!("emails: ({})", item_list(emails)));
        }
    }
    (!parts.is_empty()).then(|| format!("RDAP Analysis: {}", parts.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn related_answers_overlay_the_registry_answer() {
        let mut raw = json!({
            "ldhName": "EXAMPLE.COM",
            "events": [{"eventAction": "registration", "eventDate": "1995"}, {"no": "action"}],
            "secureDNS": {"delegationSigned": false},
        });
        merge(
            &mut raw,
            json!({
                "events": [{"eventAction": "registration", "eventDate": "1996"},
                           {"eventAction": "expiration", "eventDate": "2030"}],
                "secureDNS": {"zoneSigned": true},
                "port43": "whois.example",
            }),
        );
        assert_eq!(
            raw,
            json!({
                "ldhName": "EXAMPLE.COM",
                "events": [{"eventAction": "registration", "eventDate": "1996"},
                           {"eventAction": "expiration", "eventDate": "2030"}],
                "secureDNS": {"delegationSigned": false, "zoneSigned": true},
                "port43": "whois.example",
            })
        );
    }
}
