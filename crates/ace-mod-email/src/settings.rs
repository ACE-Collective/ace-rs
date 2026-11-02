//! The email module's settings: ace3's `analysis_module_email_analyzer` section and the two
//! global lists of the organization's domains it reads.

use schemars::JsonSchema;
use serde::Deserialize;

/// The email module's settings block.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct EmailAnalyzerSettings {
    /// Office 365 journaling also journals outbound mail. When true, an outbound journaled
    /// message is skipped unless one of its `To` addresses is in `outbound_exceptions`.
    pub scan_inbound_only: bool,
    /// Outbound journaled messages to these addresses are scanned even when
    /// `scan_inbound_only` is set.
    pub outbound_exceptions: Vec<String>,
    /// The domains the organization receives email for (ace3's global `local_email_domains`).
    pub local_email_domains: Vec<String>,
    /// The organization's own domains (ace3's global `local_domains`). A Received header whose
    /// `by` host is in one of these or in `local_email_domains` marks the perimeter.
    pub local_domains: Vec<String>,
    /// Header names for facts only some mail providers stamp. The defaults are Microsoft 365's.
    pub provider_headers: ProviderHeaders,
}

impl Default for EmailAnalyzerSettings {
    fn default() -> Self {
        // ace3's saq.default.yaml
        EmailAnalyzerSettings {
            scan_inbound_only: false,
            outbound_exceptions: Vec::new(),
            local_email_domains: Vec::new(),
            local_domains: vec!["local".to_owned()],
            provider_headers: ProviderHeaders::default(),
        }
    }
}

impl EmailAnalyzerSettings {
    /// `outbound_exception_list`: the exceptions normalized like the `To` addresses they are
    /// compared with.
    pub fn outbound_exception_list(&self) -> Vec<String> {
        self.outbound_exceptions
            .iter()
            .filter_map(|address| crate::py::normalize_email_address(address))
            .collect()
    }
}

/// ace3's `EmailProviderHeaders`. Each list is tried in order, ignoring case; an empty list turns
/// that fact off.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ProviderHeaders {
    /// Headers carrying the sending IP of the first external hop, most authoritative first.
    pub first_hop_ip: Vec<String>,
    /// Headers carrying the sending organization's tenant GUID.
    pub sender_tenant_id: Vec<String>,
    /// Headers carrying the provider's composite authentication verdict.
    pub composite_auth_result: Vec<String>,
    /// Headers carrying the provider's composite authentication reason code.
    pub composite_auth_reason: Vec<String>,
    /// Headers set to `true` when the message came by unauthenticated direct send.
    pub anonymous_direct_send: Vec<String>,
    /// Headers set to `true` when the provider treated the sender as internal.
    pub internal_org_sender: Vec<String>,
    /// Headers stating the message's direction, `Incoming` for inbound.
    pub message_directionality: Vec<String>,
}

fn strings(names: &[&str]) -> Vec<String> {
    names.iter().map(|&name| name.to_owned()).collect()
}

impl Default for ProviderHeaders {
    fn default() -> Self {
        ProviderHeaders {
            first_hop_ip: strings(&[
                "x-ms-exchange-organization-originalattributedtenantconnectingip",
                "x-ms-exchange-organization-originalclientipaddress",
                "x-sender-ip",
            ]),
            sender_tenant_id: strings(&[
                "x-ms-exchange-crosstenant-id",
                "x-ms-exchange-organization-originaltenant-id",
                "x-ms-exchange-organization-outboundhop-sender-tenantid",
            ]),
            composite_auth_result: strings(&["x-ms-exchange-organization-compauthres"]),
            composite_auth_reason: strings(&["x-ms-exchange-organization-compauthreason"]),
            anonymous_direct_send: strings(&["x-ms-exchange-organization-isanonymousdirectsend"]),
            internal_org_sender: strings(&["x-ms-exchange-organization-internalorgsender"]),
            message_directionality: strings(&["x-ms-exchange-organization-messagedirectionality"]),
        }
    }
}
