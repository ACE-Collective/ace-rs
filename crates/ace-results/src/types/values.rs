//! The results of the modules that read an observable's value (PLAN.md 7.5 batch 3), each named
//! after its ace3 class: `CommandLineAnalysis`, `FilePathAnalysis` and `FileLocationAnalysis`,
//! `NetworkIdentifierAnalysis`, `ParseURLAnalysis`, `IDNAAnalysis`, `ApexDomainAnalysis`,
//! `EmailAddressFQDNAnalysis` and `ProtectedURLAnalysis`. `ace-mod-values` writes them, and
//! `protected_url_one_drive` writes `ProtectedURLAnalysis`'s fields for a 1drv.ms link it followed.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of a `command_line_analysis` result (`saq/modules/command_line.py`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommandLineAnalysis {
    /// The Windows paths in the command line, each a `file_path` observable.
    pub file_paths: Vec<String>,
    /// The base64 runs that decoded, each written to a file.
    pub base64_payloads: Vec<Base64Payload>,
}

/// One decoded base64 run of a command line.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Base64Payload {
    /// The run as it is in the command line.
    pub base64: String,
    /// The decoded bytes' file, by its path in the alert. ace3 wrote the path on its node.
    pub file_path: String,
}

impl AnalysisType for CommandLineAnalysis {
    const NAME: &'static str = "command_line_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "command_line_analyzer";
}

/// The details of a `file_path_analysis` result (`saq/modules/file_path.py`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilePathAnalysis {
    /// What follows the last `/` or `\`.
    pub file_name: Option<String>,
    /// The `<name>` of a path that starts `<drive>:\Users\<name>\`.
    pub user_name: Option<String>,
}

impl AnalysisType for FilePathAnalysis {
    const NAME: &'static str = "file_path_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "file_path_analysis";
}

/// The details of a `file_location_analysis` result: a `host@path` value split at its first `@`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileLocationAnalysis {
    pub hostname: Option<String>,
    pub file_path: Option<String>,
}

impl AnalysisType for FileLocationAnalysis {
    const NAME: &'static str = "file_location_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "file_location_analysis";
}

/// The details of a `network_identifier_analysis` result
/// (`saq/modules/asset/network_identifier.py`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkIdentifierAnalysis {
    /// The names of the configured networks the address is in, in the configuration's order.
    pub identified_networks: Vec<String>,
}

impl AnalysisType for NetworkIdentifierAnalysis {
    const NAME: &'static str = "network_identifier_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "network_identifier";
}

/// The details of a `parse_url_analysis` result (`saq/modules/url/parser.py`): `urlsplit`'s parts
/// of the URL, or of `//<value>` for a value that starts with its host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParseUrlAnalysis {
    pub netloc: Option<String>,
    pub scheme: Option<String>,
    pub path: Option<String>,
    pub query: Option<String>,
    /// Always null, as in ace3, whose module sets its decoded query parameters on the analysis
    /// object rather than in its details, so only the summary shows them.
    pub params: Option<BTreeMap<String, String>>,
    pub fragment: Option<String>,
}

impl AnalysisType for ParseUrlAnalysis {
    const NAME: &'static str = "parse_url_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "parse_url";
}

/// The details of an `idna_analysis` result (`saq/modules/url/idna.py`): a domain's IDNA and
/// Unicode spellings, as urlfinderlib gives them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdnaAnalysis {
    /// The domain, lowercased.
    pub original: Option<String>,
    pub idna: Option<String>,
    pub unicode: Option<String>,
}

impl AnalysisType for IdnaAnalysis {
    const NAME: &'static str = "idna_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "idna_analyzer";
}

/// The details of an `apex_domain_analysis` result (`saq/modules/apex_domain.py`): the registrable
/// domain of a subdomain, which the module adds as an `fqdn` observable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApexDomainAnalysis {
    pub apex_domain: Option<String>,
}

impl AnalysisType for ApexDomainAnalysis {
    const NAME: &'static str = "apex_domain_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "apex_domain_analyzer";
}

/// The details of an `email_address_fqdn_analysis` result (`saq/modules/email/address.py`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailAddressFqdnAnalysis {
    /// Everything after the address's first `@`.
    pub domain: Option<String>,
}

impl AnalysisType for EmailAddressFqdnAnalysis {
    const NAME: &'static str = "email_address_fqdn_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "email_address_fqdn_analyzer";
}

/// The details of a `protected_url_analysis` result (`saq/modules/url/protected.py`): the service
/// that wrapped a URL and the URL inside, or `unprotected` and the URL itself. Both are null when
/// the URL couldn't be read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProtectedUrlAnalysis {
    /// ace3's `ProtectionType` value, such as `safelinks_outlook` or `unprotected`.
    pub protection_type: Option<String>,
    pub extracted_url: Option<String>,
}

impl AnalysisType for ProtectedUrlAnalysis {
    const NAME: &'static str = "protected_url_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "protected_url_analyzer";
}

/// The details of a `protected_url_one_drive_analysis` result: `ProtectedURLAnalysis`'s fields for
/// a 1drv.ms link, which ace3's `protected_url_analyzer` follows over HTTP and ace4 follows on the
/// lookup pool.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OneDriveUrlAnalysis {
    /// `one_drive`, or `unprotected` when the link led nowhere with the parameters a download needs.
    pub protection_type: Option<String>,
    pub extracted_url: Option<String>,
}

impl AnalysisType for OneDriveUrlAnalysis {
    const NAME: &'static str = "protected_url_one_drive_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "protected_url_one_drive";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn round_trip<T: AnalysisType + PartialEq + std::fmt::Debug>(details: serde_json::Value) {
        let read: T = serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        let mut extra = details;
        extra["x"] = json!(1);
        assert!(serde_json::from_value::<T>(extra).is_err());
    }

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        round_trip::<CommandLineAnalysis>(json!({
            "file_paths": ["C:\\x.exe"],
            "base64_payloads": [{"base64": "QUJD", "file_path": "command_line_base64_payload.bin"}],
        }));
        round_trip::<FilePathAnalysis>(json!({"file_name": "x.exe", "user_name": null}));
        round_trip::<FileLocationAnalysis>(json!({"hostname": "h", "file_path": "C:\\x"}));
        round_trip::<NetworkIdentifierAnalysis>(json!({"identified_networks": ["lab"]}));
        round_trip::<ParseUrlAnalysis>(json!({
            "netloc": "a.com", "scheme": "https", "path": "/", "query": "", "params": null,
            "fragment": "",
        }));
        round_trip::<IdnaAnalysis>(json!({"original": "a", "idna": "b", "unicode": "c"}));
        round_trip::<ApexDomainAnalysis>(json!({"apex_domain": "example.com"}));
        round_trip::<EmailAddressFqdnAnalysis>(json!({"domain": "example.com"}));
        round_trip::<ProtectedUrlAnalysis>(
            json!({"protection_type": "cisco", "extracted_url": "https://a.com/"}),
        );
        round_trip::<OneDriveUrlAnalysis>(
            json!({"protection_type": "unprotected", "extracted_url": "https://1drv.ms/x"}),
        );
    }
}
