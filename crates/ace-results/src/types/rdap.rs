//! `rdap_analysis`: registration data for a domain or an IP address, from RDAP (ace3's
//! `RdapAnalysis`, `saq/modules/rdap.py`).
//!
//! The keys keep ace3's names, and dates keep the form ace3 writes them in (Python's
//! `isoformat(" ")`, with the registry's own offset), so the analysis template ports as is.
//! ace3's `rdap_data` (whoisit's parse of the response) and its WHOIS fields have no
//! counterpart: `rdap_raw_json` holds the response, and the module doesn't fall back to WHOIS.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of an `rdap_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RdapAnalysis {
    /// Why the lookup failed, such as `rdap: domain not found: ...`.
    pub error: Option<String>,
    /// `rdap` when the lookup succeeded.
    pub lookup_protocol: Option<String>,
    /// Why RDAP couldn't answer, when it couldn't. ace3 then tries WHOIS.
    pub rdap_attempt_error: Option<String>,
    /// Whole days from registration to the lookup.
    pub age_created_in_days: Option<String>,
    /// Whole days from the last change to the lookup.
    pub age_last_updated_in_days: Option<String>,
    pub datetime_created: Option<String>,
    pub datetime_expiration: Option<String>,
    /// When the lookup ran.
    pub datetime_of_analysis: Option<String>,
    pub datetime_of_last_update: Option<String>,
    /// The registry's name for the domain, or the network's name for an IP address.
    pub domain_name: Option<String>,
    pub registrar: Option<String>,
    /// The RDAP URL of the object that answered.
    pub rdap_service_url: Option<String>,
    pub name_servers: Option<Vec<String>>,
    /// The first email address of each contact, sorted, at most 20.
    pub emails: Option<Vec<String>>,
    /// The network an IP address is in, such as `8.8.8.0/24`.
    pub network_cidr: Option<String>,
    pub network_name: Option<String>,
    pub country: Option<String>,
    pub ip_version: Option<u8>,
    /// How the network was assigned, such as `direct allocation`.
    pub assignment_type: Option<String>,
    /// The RDAP response, with a registrar's related response merged over the registry's.
    pub rdap_raw_json: Option<String>,
}

impl AnalysisType for RdapAnalysis {
    const NAME: &'static str = "rdap_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "rdap_analyzer";
}
