//! The newly registered domains module, a port of ace3's `NRDAnalyzer` (`saq/modules/nrd.py`).
//!
//! For an fqdn, or a URL's host, it asks the core whether the name or a parent of it down to its
//! registrable domain is in the newly registered domains list, through the `newly-registered` read
//! (PLAN.md 7.2, `crates/ace-core/src/reads.md`), which answers only for the task's own observable.
//! ace3 opens its node's SQLite copy of the list; here the core keeps one list in Postgres, which
//! its `nrd_refresh` scheduled task rebuilds from the feeds (`ace_app::nrd`).
//!
//! A name that isn't listed has no result, as ace3 creates no analysis. The feeds list recently
//! updated domains too, so a hit is verified as ace3 verifies it: RDAP is asked when the registrable
//! domain was registered (`ace_mod_rdap::CreationDates`), and a domain registered more than
//! `max_registration_age_days` ago has no result either. A lookup that finds no date keeps the hit
//! and says why. The hit is tagged `suspect:nrd`; promoting it to an alert is an observable modifier
//! rule's job, as in ace3.
//!
//! ace3 falls back to WHOIS when RDAP can't answer, which isn't ported (`tests/differences.md`).

use std::time::Duration;

use ace_mod_rdap::CreationDates;
use ace_results::types::nrd::NrdAnalysis;
use ace_results::{ObservableKind, ResultEnvelope};
use ace_sdk::http::HttpClient;
use ace_sdk::reads::{NewlyRegistered, NewlyRegisteredRequest, Read, ReadKind};
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, Resources, TaskContext};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::Deserialize;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::lookup::<NrdAnalyzer>();

/// The tag of a hit, ace3's `TAG_NRD`.
pub const TAG: &str = "suspect:nrd";

/// The module's settings: ace3's `analysis_module_nrd_analyzer` and the RDAP module's own.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct NrdSettings {
    /// A hit for a domain registered more than this many days ago, by RDAP, has no result. 0 or
    /// null turns the check off.
    pub max_registration_age_days: Option<i64>,
    /// Where IANA's RDAP bootstrap registries are.
    pub bootstrap_url: String,
    /// How long a bootstrap registry is used before it is fetched again.
    pub bootstrap_ttl_seconds: u64,
    /// The timeout of each RDAP request.
    pub request_timeout_seconds: u64,
}

impl Default for NrdSettings {
    fn default() -> Self {
        NrdSettings {
            max_registration_age_days: Some(90),
            bootstrap_url: "https://data.iana.org/rdap/".to_owned(),
            bootstrap_ttl_seconds: 24 * 3600,
            request_timeout_seconds: 30,
        }
    }
}

/// The newly registered domains module.
pub struct NrdAnalyzer {
    dates: CreationDates,
}

impl Module for NrdAnalyzer {
    const NAME: &'static str = "nrd_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn, ObservableKind::Url];
    const READS: &'static [Read] = &[NewlyRegistered::READ];
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(120),
        ..Resources::DEFAULT
    };
    type Output = NrdAnalysis;
    type Settings = NrdSettings;

    fn init(settings: &NrdSettings) -> Result<Self, ModuleError> {
        let client = HttpClient::builder()
            .timeout(Duration::from_secs(settings.request_timeout_seconds))
            .build()
            .map_err(ModuleError::other)?;
        Ok(NrdAnalyzer {
            dates: CreationDates::new(
                client,
                &settings.bootstrap_url,
                Duration::from_secs(settings.bootstrap_ttl_seconds),
            ),
        })
    }
}

impl Lookup for NrdAnalyzer {
    /// RDAP, on a hit.
    const TCP_PORTS: &'static [u16] = &[443];

    async fn analyze(
        &self,
        ctx: &TaskContext<NrdSettings>,
    ) -> Result<Outcome<NrdAnalysis>, ModuleError> {
        let answer = ctx
            .read::<NewlyRegistered>(&NewlyRegisteredRequest::default())
            .await?;
        if !answer.listed {
            return Ok(Outcome::Skipped(
                "not in the newly registered domains list".to_owned(),
            ));
        }
        let now = ctx.now();
        let mut analysis = NrdAnalysis {
            is_nrd: Some(true),
            matched_at: Some(isoformat(now)),
            ..NrdAnalysis::default()
        };
        if let Some(max_age) = ctx.settings().max_registration_age_days.filter(|d| *d != 0) {
            let domain = ace_sdk::nrd::registrable_domain(&ctx.observable().value);
            let lookup = self.dates.lookup(&domain).await?;
            match lookup.created {
                Some(created) => {
                    let age = days_between(created, now).max(0);
                    if age > max_age {
                        tracing::info!(
                            "suppressing NRD hit for {domain}: registered {age} days ago (> {max_age} \
                             day threshold), so the feed's inclusion was likely a domain update, not \
                             a registration"
                        );
                        return Ok(Outcome::Skipped(format!(
                            "{domain} was registered {age} days ago"
                        )));
                    }
                    analysis.datetime_created = Some(created.isoformat());
                    analysis.age_created_in_days = Some(created.age_in_days(now));
                    analysis.lookup_protocol = lookup.protocol.map(str::to_owned);
                }
                // fail open: keep the hit, and say why it couldn't be verified
                None => analysis.lookup_error = lookup.error,
            }
        }
        let summary = summary(&analysis);
        let mut result = ResultEnvelope::new(analysis);
        result.summary = summary;
        result.analyzed.tags = vec![TAG.to_owned()];
        Ok(Outcome::Done(result))
    }
}

/// `(now - created).days`: whole days, rounded down.
fn days_between(created: ace_mod_rdap::RdapDate, now: DateTime<Utc>) -> i64 {
    // RdapDate::age_in_days clamps at 0, as ace3's max(..., 0) does
    created.age_in_days(now).parse().unwrap_or(0)
}

/// Python's `isoformat()` of a UTC time: microseconds only when there are any.
fn isoformat(now: DateTime<Utc>) -> String {
    let micros = now.timestamp_subsec_micros();
    let fraction = if micros == 0 {
        String::new()
    } else {
        format!(".{micros:06}")
    };
    format!("{}{fraction}+00:00", now.format("%Y-%m-%dT%H:%M:%S"))
}

/// `NRDAnalysis.generate_summary`.
fn summary(analysis: &NrdAnalysis) -> Option<String> {
    if analysis.is_nrd != Some(true) {
        return None;
    }
    let base = "Newly Registered Domain: present in local NRD list";
    Some(
        match (&analysis.age_created_in_days, &analysis.lookup_error) {
            (Some(age), _) => format!("{base} (registered {age} day(s) ago)"),
            (None, Some(error)) if !error.is_empty() => {
                format!("{base} (registration age unverified: {error})")
            }
            _ => base.to_owned(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_written_as_python_s_isoformat() {
        let at: DateTime<Utc> = "2026-11-08T23:04:22.383457Z".parse().expect("a time");
        assert_eq!(isoformat(at), "2026-11-08T23:04:22.383457+00:00");
        let whole: DateTime<Utc> = "2026-11-08T23:04:22Z".parse().expect("a time");
        assert_eq!(isoformat(whole), "2026-11-08T23:04:22+00:00");
    }
}
