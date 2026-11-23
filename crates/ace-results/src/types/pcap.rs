//! The results of PLAN.md 7.5 batch 13's packet capture modules, which `ace-mod-pcap` writes, with
//! ace3's keys (`saq/modules/file_analysis/pcap.py`): `PcapAnalysis` (pcap_analyzer), the
//! `PcapCategoryAnalysis` of each of pcap_dns, pcap_tls, pcap_http and pcap_files, which ace3
//! configures as four instances of one class, `PcapTlsDecryptionAnalysis` (pcap_tls_decryption) and
//! `TlsKeylogAnalysis` (tls_keylog).
//!
//! A key that ace3 sets only on some paths is an `Option` left out when absent; one it sets to None
//! is an `Option` written as null; one it sets on some paths, null or not, is an `Option<Option<_>>`
//! (`present`). No result holds TLS secrets: a key log's lines go to tshark and nowhere else, and of
//! a capture's embedded secrets only the client randoms of the sessions they key, which a capture
//! carries in the clear, are kept.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

use crate::envelope::AnalysisType;

/// A field that's there, as `Some`, even when it's null.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(deserializer).map(Some)
}

/// Counts by observable type, as `added` and `omitted`.
pub type Counts = BTreeMap<String, u64>;

/// The details of a `pcap_analysis` result: the capture's index. When there is none, the result's
/// `error` says why the capture wasn't dissected, such as tshark's failure or its size (ace3's
/// `Analysis.error`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PcapAnalysis {
    pub index: Option<PcapIndex>,
    /// The host observables (IPs, MACs, hostnames) this result added, and those over the
    /// capture's limit of each type, by type.
    pub added: Counts,
    pub omitted: Counts,
}

impl AnalysisType for PcapAnalysis {
    const NAME: &'static str = "pcap_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "pcap_analyzer";
}

/// What tshark found in a capture, each table cut to `max_table_rows` with its whole count beside
/// it. The decryption's index (`PcapTlsDecryptionAnalysis::index`) has the tables only.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PcapIndex {
    pub dns: Vec<DnsRow>,
    pub tls: Vec<TlsRow>,
    /// Every TLS session's client random, which key logs are matched against: the plaintext
    /// index's only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_client_randoms: Option<Vec<String>>,
    /// The sha256 of every object and certificate the run carved or listed.
    pub carved_sha256: Vec<String>,
    pub http: Vec<HttpRow>,
    pub hostnames: Vec<HostnameRow>,
    pub objects: Vec<ObjectRow>,
    pub certificates: Vec<CertificateRow>,
    pub dns_total: u64,
    pub tls_total: u64,
    pub http_total: u64,
    pub hostnames_total: u64,
    pub objects_total: u64,
    pub certificates_total: u64,
    /// DNS, TLS, HTTP, DHCP and NBNS are read from this many packets at the start.
    pub field_packet_limit: u64,
    /// The statistics pass: packets, endpoints and flows. The plaintext index's only; empty when
    /// the pass failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statistics: Option<Statistics>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub statistics_error: Option<Option<String>>,
    /// capinfos' summary of the capture, null when it failed.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub capture: Option<Option<Capture>>,
    /// The pcapng's Decryption Secrets Blocks, when it has any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedded_secrets: Option<EmbeddedSecrets>,
}

/// A name DNS saw, as asked, answered, a CNAME's target or a zone's owner.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DnsRow {
    pub name: String,
    /// The A, AAAA and CNAME answers to it, in the order first seen.
    pub answers: Vec<String>,
    pub queries: u64,
    pub responses: u64,
    /// `cname` and `zone`, when it was seen as one.
    pub seen_as: Vec<String>,
    /// When each answer was first returned, in epoch seconds: once a response was seen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer_times: Option<BTreeMap<String, f64>>,
}

/// A TLS session, by its flow (`tcp:<stream>`), with what its ClientHello said once one was seen.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TlsRow {
    pub flow: String,
    /// The sha256 of the certificates its handshake carried.
    pub certificates: Vec<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub client: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub server: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub sni: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub ja4: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_random: Option<Option<String>>,
}

/// An HTTP request, HTTP/1 or HTTP/2, with its response's status and type once one was seen.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpRow {
    pub method: Option<String>,
    pub url: Option<String>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub status: Option<String>,
    pub content_type: Option<String>,
}

/// A hostname DHCP or NBNS announced.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostnameRow {
    pub name: String,
    /// `dhcp` or `nbns`.
    pub source: String,
    pub mac: Option<String>,
}

/// An object tshark exported.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObjectRow {
    /// `http`, `smb`, `ftp-data`, `tftp` or `imf`.
    pub protocol: String,
    pub file_name: String,
    pub sha256: String,
    pub size: u64,
    /// Where it was carved to, relative to the capture's directory; null past the carve's limit.
    pub path: Option<String>,
    /// For an HTTP object: the one request whose URL ends in its name, if exactly one does.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub url: Option<Option<String>>,
}

/// A certificate a TLS handshake carried, with its names when it parses.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CertificateRow {
    pub sha256: String,
    /// Where it was carved to, relative to the capture's directory; null past the carve's limit or
    /// when an earlier run carved it.
    pub path: Option<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub subject: Option<Option<String>>,
    /// The first 10 SAN DNS names other than the subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sans: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub san_total: Option<u64>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub issuer: Option<Option<String>>,
}

/// capinfos' summary of a capture.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub format: Option<String>,
    pub size: Option<u64>,
    pub packets: Option<u64>,
    /// Its first and last packets' times, in epoch seconds, and the time between them.
    pub first: Option<f64>,
    pub last: Option<f64>,
    pub duration: Option<f64>,
    pub application: Option<String>,
    pub interfaces: Option<u64>,
    pub encapsulations: Vec<String>,
    pub strict_time_order: Option<bool>,
    /// The capture's name in the alert.
    pub file_name: String,
}

/// The statistics pass: every packet's count and bytes, the endpoints and the conversations, each
/// table most packets first. Each key is absent when the pass failed.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Statistics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packets: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<Vec<Endpoint>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<Vec<Endpoint>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flows: Option<Vec<Flow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flows_total: Option<u64>,
}

/// An Ethernet or IP endpoint.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub address: String,
    pub packets: u64,
    pub bytes: u64,
}

/// A TCP or UDP conversation.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Flow {
    pub protocol: String,
    pub a: String,
    pub b: String,
    pub frames: u64,
    /// As tshark prints it, such as `3093 bytes` or `12 kB`.
    pub bytes: String,
    /// Seconds after the capture's first packet.
    pub start: f64,
    pub duration: f64,
}

/// A pcapng's Decryption Secrets Blocks: how many of each kind, the TLS secrets' labels, and the
/// sessions whose keys they hold, by client random. Never the secrets.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedSecrets {
    pub types: Counts,
    pub label_counts: Counts,
    pub keyed_client_randoms: Vec<String>,
}

/// One category of a capture's index, as each of pcap_dns, pcap_tls, pcap_http and pcap_files
/// writes it: the category's rows, with what it added and omitted.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PcapCategory<R> {
    /// `dns`, `tls`, `http` or `files`.
    pub category: String,
    pub capture: Option<Capture>,
    pub field_packet_limit: Option<u64>,
    pub rows: Vec<R>,
    pub total: u64,
    /// pcap_tls's: the capture's certificates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<CertificateRow>>,
    pub added: Counts,
    pub omitted: Counts,
}

macro_rules! category_type {
    ($(#[$doc:meta])* $name:ident, $row:ty, $type_name:literal, $module:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(pub PcapCategory<$row>);

        impl AnalysisType for $name {
            const NAME: &'static str = $type_name;
            const VERSION: u32 = 1;
            const MODULE: &'static str = $module;
        }
    };
}

category_type!(
    /// pcap_dns's `PcapCategoryAnalysis`: the names DNS saw.
    PcapDnsAnalysis, DnsRow, "pcap_dns_analysis", "pcap_dns"
);
category_type!(
    /// pcap_tls's `PcapCategoryAnalysis`: the TLS sessions, and the certificates.
    PcapTlsAnalysis, TlsRow, "pcap_tls_analysis", "pcap_tls"
);
category_type!(
    /// pcap_http's `PcapCategoryAnalysis`: the HTTP requests.
    PcapHttpAnalysis, HttpRow, "pcap_http_analysis", "pcap_http"
);
category_type!(
    /// pcap_files's `PcapCategoryAnalysis`: the objects tshark exported.
    PcapFilesAnalysis, ObjectRow, "pcap_files_analysis", "pcap_files"
);

/// The details of a `pcap_tls_decryption_analysis` result: the key logs found in the alert, what
/// they decrypted, and what that added beyond the plaintext index.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PcapTlsDecryptionAnalysis {
    /// Each key log applied, by its sha256 and name, with its labels' counts. Never its lines.
    pub keylogs: Vec<KeylogSource>,
    /// The capture's TLS sessions, and those any key, embedded or logged, is for.
    pub sessions: u64,
    pub sessions_with_keys: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions_with_embedded_keys: Option<u64>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub capture: Option<Option<Capture>>,
    /// The decrypted run's tables, when tshark ran.
    pub index: Option<PcapIndex>,
    pub added: Counts,
    pub omitted: Counts,
}

/// A key log a decryption applied.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeylogSource {
    pub sha256: String,
    pub file_name: String,
    pub label_counts: Counts,
}

impl AnalysisType for PcapTlsDecryptionAnalysis {
    const NAME: &'static str = "pcap_tls_decryption_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "pcap_tls_decryption";
}

/// The details of a `tls_keylog_analysis` result: a TLS key log's labels and sessions. The secrets
/// are never stored.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TlsKeylogAnalysis {
    pub label_counts: Counts,
    /// How many sessions it has keys for, by client random.
    pub client_randoms: u64,
    /// The captures a late key log was applied to, and those out of time, by sha256: ace3's late
    /// application, which ace-rs has no case for (`ace-mod-pcap`'s docs), so both stay empty.
    pub applied_to: Vec<String>,
    pub skipped: Vec<String>,
}

impl AnalysisType for TlsKeylogAnalysis {
    const NAME: &'static str = "tls_keylog_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "tls_keylog";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_ace3_sets_to_none_are_null_and_keys_it_leaves_out_are_absent() {
        let row = TlsRow {
            flow: "tcp:0".into(),
            certificates: Vec::new(),
            sni: Some(None),
            ..TlsRow::default()
        };
        let value = serde_json::to_value(&row).unwrap();
        assert_eq!(
            value,
            json!({"flow": "tcp:0", "certificates": [], "sni": null})
        );
        assert_eq!(serde_json::from_value::<TlsRow>(value).unwrap(), row);
        let dns: PcapDnsAnalysis = serde_json::from_value(json!({
            "category": "dns", "capture": null, "field_packet_limit": 50000, "rows": [],
            "total": 0, "added": {}, "omitted": {}
        }))
        .unwrap();
        assert_eq!(dns.0.category, "dns");
    }
}
