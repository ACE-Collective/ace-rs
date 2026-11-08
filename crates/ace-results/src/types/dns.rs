//! `fqdn_analysis`: what a domain name resolves to, and whether it resolves at all (ace3's
//! `FQDNAnalysis`, `saq/modules/dns.py`). `ace-mod-dns` writes it (PLAN.md 7.4).
//!
//! Every key is always there, null when the lookup didn't get that far, as ace3 writes them.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of an `fqdn_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FqdnAnalysis {
    /// The first of `all_resolutions`, which the module adds as an ip observable.
    pub ip_address: Option<String>,
    /// How many addresses the name has.
    pub resolution_count: Option<u64>,
    /// The targets of the CNAME records in the answer, in its order, without their final dot.
    pub aliaslist: Vec<String>,
    /// The name's IPv4 addresses, sorted as text.
    pub all_resolutions: Vec<String>,
    /// `ok`, `nxdomain`, `no_answer` or `dns_error`. Only `nxdomain` and `no_answer` say anything
    /// about the name; `dns_error` means it couldn't be looked up.
    pub status: Option<String>,
    /// The MX exchanges, sorted, for a name that is its own registrable domain. Null when not
    /// looked up, or when the lookup failed.
    pub mx: Option<Vec<String>>,
    /// For a registrable domain: whether a name under it that can't exist resolves.
    pub wildcard_dns: Option<bool>,
}

impl AnalysisType for FqdnAnalysis {
    const NAME: &'static str = "fqdn_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "fqdn_analyzer";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let details = json!({
            "ip_address": "192.0.2.10", "resolution_count": 2, "aliaslist": [],
            "all_resolutions": ["192.0.2.10", "192.0.2.2"], "status": "ok",
            "mx": ["mail.example.com"], "wildcard_dns": false,
        });
        let read: FqdnAnalysis = serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        let mut unknown = details;
        unknown["x"] = json!(1);
        assert!(serde_json::from_value::<FqdnAnalysis>(unknown).is_err());
    }
}
