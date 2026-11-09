//! `x509_analysis`: a certificate's names, dates and extensions (ace3's `X509Analysis`,
//! `saq/modules/x509.py`). `ace-mod-files` writes it, on `ace-x509` (PLAN.md 7.5 batch 2).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// A certificate's serial number. ace3 writes a Python int, which can pass 64 bits, as most
/// serials do; JSON numbers here are 64 bits, so a larger one is its decimal text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum SerialNumber {
    Number(i64),
    Text(String),
}

/// The details of an `x509_analysis` result, with ace3's keys.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct X509Analysis {
    /// The issuer's name as RFC 4514 writes it, as cryptography gives it.
    pub issuer: Option<String>,
    pub subject: Option<String>,
    /// UTC, as ace3 writes a datetime: `2024-01-31T12:00:00.000000+0000`.
    pub not_valid_before: Option<String>,
    pub not_valid_after: Option<String>,
    pub serial_number: Option<SerialNumber>,
    /// The last common name of the subject, None when it has none or it's empty.
    pub common_name: Option<String>,
    /// The SHA-256 of the certificate's DER.
    pub sha256_hash: Option<String>,
    /// Each extension as cryptography's objects print, as ace3's `get_readable_extensions`
    /// builds the tree. None when cryptography can't parse them.
    pub extensions: Option<serde_json::Value>,
    pub subject_alternative_names: SubjectAlternativeNames,
}

/// The subject alternative names, in the certificate's order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubjectAlternativeNames {
    pub san_ip_addresses: Vec<String>,
    pub san_dns_names: Vec<String>,
}

impl AnalysisType for X509Analysis {
    const NAME: &'static str = "x509_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "x509_analyzer";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let details = json!({
            "issuer": "CN=a", "subject": "CN=b", "not_valid_before": "2024-01-31T12:00:00.000000+0000",
            "not_valid_after": "2025-01-31T12:00:00.000000+0000", "serial_number": "123456789012345678901234567890",
            "common_name": "b", "sha256_hash": "00", "extensions": [{"BasicConstraints": ["ca: False"]}],
            "subject_alternative_names": {"san_ip_addresses": [], "san_dns_names": ["b"]},
        });
        let read: X509Analysis = serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        let small: X509Analysis = serde_json::from_value(json!({
            "issuer": null, "subject": null, "not_valid_before": null, "not_valid_after": null,
            "serial_number": 7, "common_name": null, "sha256_hash": null, "extensions": null,
            "subject_alternative_names": {"san_ip_addresses": [], "san_dns_names": []},
        }))
        .expect("reads");
        assert_eq!(small.serial_number, Some(SerialNumber::Number(7)));
        let mut extra = details;
        extra["x"] = json!(1);
        assert!(serde_json::from_value::<X509Analysis>(extra).is_err());
    }
}
