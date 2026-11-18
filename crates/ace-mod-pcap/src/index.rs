//! The capture's index, from tshark's runs, as ace3's pcap.py builds it (`dissect`, `build_index`,
//! `merge_index`, `_collect_carved_files`, `_link_http_objects`, `certificate_names`).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use ace_pycompat::pystr;
use ace_results::types::pcap::{
    CertificateRow, DnsRow, HostnameRow, HttpRow, ObjectRow, PcapIndex, Statistics, TlsRow,
};
use ace_results::{NewFile, StoredFile};
use ace_sdk::{ModuleError, TaskContext};
use regex::Regex;

use crate::config::{
    CAPINFOS_TIMEOUT, MAX_EXTRACTED_FILES, MAX_FIELD_PACKETS, MAX_TABLE_ROWS, TSHARK_TIMEOUT,
};
use crate::tshark::{self, Layers, PcapError, all, first};
use crate::{alert_dir, sha256_file, sha256_hex};

/// The tables of the index whose rows a category's analysis copies.
pub const CATEGORY_DNS: &str = "dns";
pub const CATEGORY_TLS: &str = "tls";
pub const CATEGORY_HTTP: &str = "http";
pub const CATEGORY_FILES: &str = "files";
pub const CATEGORY_HOSTS: &str = "hosts";

// the owner of an SOA or NS record (usually from the authority section of a reply with no answer)
// is a zone
const DNS_ZONE_RECORD_TYPES: [&str; 2] = ["2", "6"];
// the EDNS OPT pseudo-record, which every modern resolver adds; its owner is the root, not a name
const DNS_OPT_RECORD_TYPE: &str = "41";
// how tshark prints the root domain
const DNS_ROOT_NAME: &str = "<root>";
// TLS handshake message types
const TLS_CLIENT_HELLO: &str = "1";
const TLS_CERTIFICATE: &str = "11";
/// The SAN names of a certificate kept.
const MAX_CERTIFICATE_SANS: usize = 10;

static NBNS_SUFFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<[0-9a-fA-F]{2}>.*$").expect("the pattern compiles"));

/// A certificate a handshake carried: its row, and its DER as tshark printed it, for the sessions.
pub struct Certificate {
    pub row: CertificateRow,
    pub der_hex: String,
}

/// What a dissection gave: the index, and the files it carved, which the result stores or adds.
pub struct Dissection {
    pub index: PcapIndex,
    pub carved: Vec<NewFile>,
}

/// Where a dissection's files go, beside the capture: `<name>.pcap_objects` for the plaintext run,
/// `<name>.pcap_decrypted` for a decryption.
pub struct Target<'a> {
    /// The capture's path in the alert.
    pub capture_path: &'a str,
    /// `pcap_objects` or `pcap_decrypted`.
    pub suffix: &'a str,
}

impl Target<'_> {
    /// The carve's directory, relative to the capture's: `<name>.<suffix>`.
    fn dir(&self) -> String {
        let name = self
            .capture_path
            .rsplit('/')
            .next()
            .unwrap_or(self.capture_path);
        format!("{name}.{}", self.suffix)
    }
}

/// ace3's `dissect`: tshark's runs over the capture, into its index. With `statistics`, capinfos and
/// the statistics run first, as for the plaintext index; with `keylog`, a file of key log lines the
/// field run decrypts with. Files in `known_sha256` aren't carved again. The capture's failure is
/// the outer error's absence and the inner's presence.
pub fn dissect<S>(
    ctx: &TaskContext<S>,
    capture: &Path,
    target: &Target<'_>,
    keylog: Option<&Path>,
    known_sha256: &BTreeSet<String>,
    statistics: bool,
) -> Result<Result<Dissection, PcapError>, ModuleError> {
    let input = capture.display().to_string();
    let mut reads: Vec<PathBuf> = vec![capture.to_owned()];
    let mut index_statistics = None;
    let mut statistics_error = None;
    let mut capture_summary = None;
    if statistics {
        ctx.check_cancelled()?;
        let args = vec!["-M".to_owned(), "-S".to_owned(), input.clone()];
        match tshark::run(ctx, "capinfos", args, &reads, CAPINFOS_TIMEOUT, false)? {
            Ok(ran) => capture_summary = Some(tshark::parse_capinfos(&ran.stdout)),
            // only the page header needs it; the dissection does not
            Err(e) => tracing::info!("no capture metadata: {}", e.0),
        }
        ctx.check_cancelled()?;
        let mut args = vec!["-n".to_owned(), "-r".to_owned(), input.clone()];
        args.extend(tshark::STATISTICS_ARGS.iter().map(|a| (*a).to_owned()));
        match tshark::run(ctx, "tshark", args, &reads, TSHARK_TIMEOUT, false)? {
            Ok(ran) => {
                index_statistics = Some(tshark::parse_statistics(&ran.stdout, MAX_TABLE_ROWS)?)
            }
            Err(e) => {
                // a line per conversation can outgrow the output cap (a scan, heavy DNS); only the
                // endpoint and flow tables need it, so the field pass still runs
                tracing::info!("no packet statistics: {}", e.0);
                statistics_error = Some(e.0);
            }
        }
        if let Some(packets) = index_statistics
            .as_ref()
            .and_then(|s: &Statistics| s.packets)
            && packets > MAX_FIELD_PACKETS
        {
            tracing::info!(
                "the capture has {packets} packets: DNS, TLS and HTTP are read from the first {MAX_FIELD_PACKETS}"
            );
        }
    }
    if let Some(keylog) = keylog {
        reads.push(keylog.to_owned());
    }
    // tshark's JSON is about 1 kB a packet and must fit under the runner's output cap. The limit is
    // a display filter, not -c, so tshark still reads every packet and the object export covers the
    // whole capture.
    let mut args = vec!["-n".to_owned(), "-r".to_owned(), input];
    args.extend(tshark::field_args(MAX_FIELD_PACKETS, keylog));
    ctx.check_cancelled()?;
    let ran = match tshark::run(ctx, "tshark", args, &reads, TSHARK_TIMEOUT, true)? {
        Ok(ran) => ran,
        Err(e) => return Ok(Err(e)),
    };
    let packets = match tshark::parse_fields(&ran.stdout) {
        Ok(packets) => packets,
        Err(e) => return Ok(Err(e)),
    };
    let (objects, certificates, carved) =
        collect_carved_files(ctx, &ran.output, target, &packets, known_sha256)?;
    let mut index = build_index(&packets, certificates, objects, MAX_TABLE_ROWS);
    index.field_packet_limit = MAX_FIELD_PACKETS;
    link_http_objects(&mut index);
    if statistics {
        index.statistics = Some(index_statistics.unwrap_or_default());
        index.statistics_error = Some(statistics_error);
        index.capture = Some(capture_summary);
    }
    Ok(Ok(Dissection { index, carved }))
}

/// The objects, certificates and files a carve gave.
type Carved = (Vec<ObjectRow>, Vec<Certificate>, Vec<NewFile>);

/// `_collect_carved_files`: the objects tshark exported, protocol by protocol, each directory's in
/// name order, then the certificates the handshakes carried, the first `MAX_EXTRACTED_FILES` of
/// them, the objects first, written to the task's outputs; content in `known_sha256` is skipped.
/// The rows' paths are relative to the capture's directory, as ace3's are.
fn collect_carved_files<S>(
    ctx: &TaskContext<S>,
    output: &ace_sdk::tools::ToolOutput,
    target: &Target<'_>,
    packets: &[Layers],
    known_sha256: &BTreeSet<String>,
) -> Result<Carved, ModuleError> {
    let mut objects = Vec::new();
    let mut certificates = Vec::new();
    let mut carved = Vec::new();
    let mut remaining = MAX_EXTRACTED_FILES;
    let dir = target.dir();
    let alert_base = alert_dir(target.capture_path);
    // what this carve wrote, as ace3's `_unique_path` finds what's already there
    let mut used: BTreeSet<String> = BTreeSet::new();
    let mut seen_sha256: BTreeSet<String> = BTreeSet::new();
    // a payload matters more than the certificates of the handshakes: the runner keeps only plain
    // files with one link, and none it couldn't move, so nothing is followed out of tshark's directory
    for protocol in tshark::EXPORT_OBJECT_PROTOCOLS {
        let prefix = format!("objects/{protocol}/");
        let mut names: Vec<(&str, &Path)> = output
            .outputs
            .iter()
            .filter_map(|(name, path)| {
                let file_name = name.strip_prefix(&prefix)?;
                (!file_name.contains('/')).then_some((file_name, path.as_path()))
            })
            .collect();
        names.sort_by(|a, b| a.0.cmp(b.0));
        for (file_name, source) in names {
            let sha256 = sha256_file(source)?;
            if known_sha256.contains(&sha256) || !seen_sha256.insert(sha256.clone()) {
                continue;
            }
            let size = std::fs::metadata(source)?.len();
            let mut row = ObjectRow {
                protocol: protocol.to_owned(),
                file_name: file_name.to_owned(),
                sha256,
                size,
                path: None,
                url: None,
            };
            if remaining > 0 {
                let relative = unique_path(&mut used, &format!("{dir}/{protocol}/{file_name}"));
                // a name the alert can't hold, such as `..`, is listed without being carved
                if let Ok(file) = ctx.write_file_from(
                    &format!("{alert_base}{relative}"),
                    &mut File::open(source)?,
                    None,
                ) {
                    carved.push(file);
                    row.path = Some(relative);
                    remaining -= 1;
                }
            }
            objects.push(row);
        }
    }
    let mut seen_der: BTreeSet<String> = BTreeSet::new();
    for layers in packets {
        for der_hex in all(layers, "tls.handshake.certificate") {
            let der_hex = pystr::lower(&der_hex.replace(':', "")).into_owned();
            if !seen_der.insert(der_hex.clone()) {
                continue;
            }
            // tshark printed something that is not a certificate's bytes; there is nothing to carve
            let Some(der) = from_hex(&der_hex) else {
                continue;
            };
            let sha256 = sha256_hex(&der);
            let mut row = certificate_names(&der);
            row.sha256 = sha256.clone();
            if !known_sha256.contains(&sha256) && remaining > 0 {
                let relative = format!("{dir}/certificates/{sha256}.der");
                let file = ctx.write_file(&format!("{alert_base}{relative}"), &der, None)?;
                carved.push(file);
                row.path = Some(relative);
                remaining -= 1;
            }
            certificates.push(Certificate { row, der_hex });
        }
    }
    Ok((objects, certificates, carved))
}

/// `_unique_path`: the path, or the first free `<stem>_NNN<ext>` next to it.
fn unique_path(used: &mut BTreeSet<String>, path: &str) -> String {
    let chosen = if used.contains(path) {
        let (stem, ext) = splitext(path);
        (0..)
            .map(|i| format!("{stem}_{i:03}{ext}"))
            .find(|p| !used.contains(p))
            .expect("a free name")
    } else {
        path.to_owned()
    };
    used.insert(chosen.clone());
    chosen
}

/// `os.path.splitext`: the extension is from the name's last dot that isn't one of its leading
/// dots.
fn splitext(path: &str) -> (&str, &str) {
    let name_start = path.rfind('/').map_or(0, |i| i + 1);
    let name = &path[name_start..];
    let leading = name.len() - name.trim_start_matches('.').len();
    match name[leading..].rfind('.') {
        Some(dot) => path.split_at(name_start + leading + dot),
        None => (path, ""),
    }
}

/// `bytes.fromhex`: pairs of hex digits, whitespace allowed between them; None where it raises.
fn from_hex(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c.is_ascii_whitespace() {
            continue;
        }
        let high = c.to_digit(16)?;
        let low = chars.next()?.to_digit(16)?;
        bytes.push((high * 16 + low) as u8);
    }
    Some(bytes)
}

/// `certificate_names`: the subject, the other SAN DNS names (the first 10) and the issuer of a DER
/// certificate, for the analyst; nothing when it doesn't parse, as a certificate in a capture is
/// whatever the peer sent.
pub fn certificate_names(der: &[u8]) -> CertificateRow {
    let names = || -> Result<CertificateRow, ace_x509::PyErr> {
        let cert = ace_x509::load_der_x509_certificate(der)?;
        let subject = name_text(&cert.subject()?);
        let sans: Vec<String> = cert
            .san_dns_names()?
            .into_iter()
            .filter(|name| Some(name) != subject.as_ref())
            .collect();
        Ok(CertificateRow {
            subject: Some(subject),
            san_total: Some(sans.len() as u64),
            sans: Some(sans.into_iter().take(MAX_CERTIFICATE_SANS).collect()),
            issuer: Some(name_text(&cert.issuer()?)),
            ..CertificateRow::default()
        })
    };
    names().unwrap_or_default()
}

/// `_name_text`: a name's first common name, else its first organization, else its RFC 4514
/// string, or None for an empty one.
fn name_text(name: &ace_x509::Name) -> Option<String> {
    for oid in ["2.5.4.3", "2.5.4.10"] {
        if let Some(attribute) = name.attributes().find(|a| a.oid.to_string() == oid) {
            return Some(match &attribute.value {
                ace_x509::AttrValue::Str(s) => s.clone(),
                ace_x509::AttrValue::Bytes(b) => ace_pycompat::repr::repr_bytes(b),
            });
        }
    }
    Some(name.rfc4514_string()).filter(|s| !s.is_empty())
}

/// `_epoch`: the packet's time, epoch seconds.
fn epoch(layers: &Layers) -> Option<f64> {
    first(layers, "frame.time_epoch").and_then(|t| pystr::strip(t).parse().ok())
}

/// `_flow_key`.
fn flow_key(layers: &Layers) -> Option<String> {
    if let Some(stream) = layers.get("tcp.stream") {
        return Some(format!("tcp:{}", stream.first().map_or("", String::as_str)));
    }
    layers
        .get("udp.stream")
        .map(|stream| format!("udp:{}", stream.first().map_or("", String::as_str)))
}

/// `_endpoints`: `address:port` of each side, a missing port written as Python writes None.
fn endpoints(layers: &Layers) -> (Option<String>, Option<String>) {
    let pick = |a: &str, b: &str| {
        first(layers, a)
            .filter(|v| !v.is_empty())
            .or(first(layers, b).filter(|v| !v.is_empty()))
    };
    let src = pick("ip.src", "ipv6.src");
    let dst = pick("ip.dst", "ipv6.dst");
    let sport = pick("tcp.srcport", "udp.srcport").unwrap_or("None");
    let dport = pick("tcp.dstport", "udp.dstport").unwrap_or("None");
    (
        src.map(|s| format!("{s}:{sport}")),
        dst.map(|d| format!("{d}:{dport}")),
    )
}

/// An ordered dict of rows by key, as ace3's tables are.
struct Table<R> {
    rows: Vec<R>,
    by_key: HashMap<String, usize>,
}

impl<R> Table<R> {
    fn new() -> Self {
        Table {
            rows: Vec::new(),
            by_key: HashMap::new(),
        }
    }

    /// `setdefault(key, make())`.
    fn entry(&mut self, key: &str, make: impl FnOnce() -> R) -> &mut R {
        let i = *self.by_key.entry(key.to_owned()).or_insert_with(|| {
            self.rows.push(make());
            self.rows.len() - 1
        });
        &mut self.rows[i]
    }

    fn get_mut(&mut self, key: &str) -> Option<&mut R> {
        self.by_key.get(key).map(|&i| &mut self.rows[i])
    }

    /// `d[key] = row`: in the key's old place if it had one.
    fn set(&mut self, key: &str, row: R) {
        match self.by_key.get(key) {
            Some(&i) => self.rows[i] = row,
            None => {
                self.by_key.insert(key.to_owned(), self.rows.len());
                self.rows.push(row);
            }
        }
    }
}

/// `build_index`: the parts of the capture that become observables, from the field run's packets.
pub fn build_index(
    packets: &[Layers],
    certificates: Vec<Certificate>,
    objects: Vec<ObjectRow>,
    max_rows: usize,
) -> PcapIndex {
    let mut dns: Table<DnsRow> = Table::new();
    let mut tls: Table<TlsRow> = Table::new();
    let mut http: Table<HttpRow> = Table::new();
    let mut hostnames: Table<HostnameRow> = Table::new();
    let certificate_by_der: HashMap<&str, &str> = certificates
        .iter()
        .map(|c| (c.der_hex.as_str(), c.row.sha256.as_str()))
        .collect();
    let lower = |s: &str| pystr::lower(s).into_owned();
    let new_dns = |name: &str| DnsRow {
        name: name.to_owned(),
        ..DnsRow::default()
    };

    for layers in packets {
        let frame = first(layers, "frame.number").unwrap_or("").to_owned();
        let resp_names = all(layers, "dns.resp.name");
        let resp_types = all(layers, "dns.resp.type");
        // dns.resp.name and dns.resp.type are parallel: one entry per resource record
        let record_names = resp_names.iter().enumerate().filter_map(|(i, name)| {
            (resp_types.get(i).map(String::as_str) != Some(DNS_OPT_RECORD_TYPE)).then_some(name)
        });
        let cnames = all(layers, "dns.cname");
        // every name gets a row, also one never looked up (a CNAME target, a zone)
        for name in all(layers, "dns.qry.name")
            .iter()
            .chain(record_names)
            .chain(cnames)
        {
            let key = lower(name);
            if key != DNS_ROOT_NAME {
                dns.entry(&key, || new_dns(&key));
            }
        }
        let zones = resp_names
            .iter()
            .zip(resp_types)
            .filter(|(_, t)| DNS_ZONE_RECORD_TYPES.contains(&t.as_str()))
            .map(|(n, _)| (n, "zone"));
        for (name, role) in cnames.iter().map(|n| (n, "cname")).chain(zones) {
            let key = lower(name);
            if key == DNS_ROOT_NAME {
                continue;
            }
            let row = dns.entry(&key, || new_dns(&key));
            if !row.seen_as.iter().any(|r| r == role) {
                row.seen_as.push(role.to_owned());
            }
        }
        if layers.contains_key("dns.qry.name") {
            let is_response = matches!(
                first(layers, "dns.flags.response"),
                Some("True" | "1" | "true")
            );
            let answers: Vec<&String> = all(layers, "dns.a")
                .iter()
                .chain(all(layers, "dns.aaaa"))
                .chain(cnames)
                .collect();
            for name in all(layers, "dns.qry.name") {
                // a root query (". NS", a resolver priming itself) names nothing
                let key = lower(name);
                if key == DNS_ROOT_NAME {
                    continue;
                }
                let row = dns.entry(&key, || new_dns(&key));
                if is_response {
                    row.responses += 1;
                    let seen_at = epoch(layers);
                    let times = row.answer_times.get_or_insert_with(BTreeMap::new);
                    for answer in &answers {
                        if !row.answers.contains(answer) {
                            row.answers.push((*answer).clone());
                        }
                        // when the answer was first returned: the time an answer IP observable carries
                        if let Some(seen_at) = seen_at
                            && times.get(answer.as_str()).is_none_or(|t| seen_at < *t)
                        {
                            times.insert((*answer).clone(), seen_at);
                        }
                    }
                } else {
                    row.queries += 1;
                }
            }
        }

        let handshake_types = all(layers, "tls.handshake.type");
        let flow = flow_key(layers);
        if let Some(flow) = &flow
            && handshake_types.iter().any(|t| t == TLS_CLIENT_HELLO)
        {
            let (client, server) = endpoints(layers);
            let session = tls.entry(flow, || TlsRow {
                flow: flow.clone(),
                ..TlsRow::default()
            });
            session.client = Some(client);
            session.server = Some(server);
            session.sni =
                Some(first(layers, "tls.handshake.extensions_server_name").map(str::to_owned));
            session.ja4 = Some(first(layers, "tls.handshake.ja4").map(str::to_owned));
            session.client_random = Some(
                Some(lower(first(layers, "tls.handshake.random").unwrap_or("")))
                    .filter(|r| !r.is_empty()),
            );
        }
        if let Some(flow) = &flow
            && handshake_types.iter().any(|t| t == TLS_CERTIFICATE)
        {
            let session = tls.entry(flow, || TlsRow {
                flow: flow.clone(),
                ..TlsRow::default()
            });
            for der_hex in all(layers, "tls.handshake.certificate") {
                let key = lower(&der_hex.replace(':', ""));
                if let Some(sha256) = certificate_by_der.get(key.as_str())
                    && !session.certificates.iter().any(|c| c == sha256)
                {
                    session.certificates.push((*sha256).to_owned());
                }
            }
        }

        let owned = |field: &str| first(layers, field).map(str::to_owned);
        if layers.contains_key("http.request.method") {
            http.set(
                &frame,
                HttpRow {
                    method: owned("http.request.method"),
                    url: owned("http.request.full_uri"),
                    host: owned("http.host"),
                    user_agent: owned("http.user_agent"),
                    status: None,
                    content_type: None,
                },
            );
        } else if layers.contains_key("http.response.code")
            && let Some(request) = http.get_mut(first(layers, "http.request_in").unwrap_or(""))
            && request.status.is_none()
        {
            request.status = owned("http.response.code");
            request.content_type = owned("http.content_type");
        }

        let methods = all(layers, "http2.headers.method");
        let schemes = all(layers, "http2.headers.scheme");
        let authorities = all(layers, "http2.headers.authority");
        let paths = all(layers, "http2.headers.path");
        if !methods.is_empty()
            && methods.len() == schemes.len()
            && schemes.len() == authorities.len()
            && authorities.len() == paths.len()
        {
            let agents = all(layers, "http2.headers.user_agent");
            for (i, method) in methods.iter().enumerate() {
                http.set(
                    &format!("{frame}:{i}"),
                    HttpRow {
                        method: Some(method.clone()),
                        url: Some(format!("{}://{}{}", schemes[i], authorities[i], paths[i])),
                        host: Some(authorities[i].clone()),
                        user_agent: agents.get(i).cloned(),
                        status: None,
                        content_type: None,
                    },
                );
            }
        }

        for name in all(layers, "dhcp.option.hostname") {
            hostnames.entry(&lower(name), || HostnameRow {
                name: name.clone(),
                source: "dhcp".to_owned(),
                mac: owned("dhcp.hw.mac_addr"),
            });
        }
        for name in all(layers, "nbns.name") {
            let name = NBNS_SUFFIX.replace_all(name, "");
            let name = pystr::strip(&name);
            if !name.is_empty() && !name.starts_with('_') {
                hostnames.entry(&lower(name), || HostnameRow {
                    name: name.to_owned(),
                    source: "nbns".to_owned(),
                    mac: None,
                });
            }
        }
    }

    // key logs are matched against every session, not only the ones the table keeps
    let tls_client_randoms: BTreeSet<String> = tls
        .rows
        .iter()
        .filter_map(|s| s.client_random.clone().flatten())
        .collect();
    // and a later decryption knows every file this run carved or listed, not only the rows kept
    let carved_sha256: BTreeSet<String> = objects
        .iter()
        .map(|o| o.sha256.clone())
        .chain(certificates.iter().map(|c| c.row.sha256.clone()))
        .collect();
    let certificates: Vec<CertificateRow> = certificates.into_iter().map(|c| c.row).collect();
    fn cut<R>(mut rows: Vec<R>, max_rows: usize) -> (u64, Vec<R>) {
        let total = rows.len() as u64;
        rows.truncate(max_rows);
        (total, rows)
    }
    let (dns_total, dns) = cut(dns.rows, max_rows);
    let (tls_total, tls) = cut(tls.rows, max_rows);
    let (http_total, http) = cut(http.rows, max_rows);
    let (hostnames_total, hostnames) = cut(hostnames.rows, max_rows);
    let (objects_total, objects) = cut(objects, max_rows);
    let (certificates_total, certificates) = cut(certificates, max_rows);
    PcapIndex {
        dns,
        tls,
        tls_client_randoms: Some(tls_client_randoms.into_iter().collect()),
        carved_sha256: carved_sha256.into_iter().collect(),
        http,
        hostnames,
        objects,
        certificates,
        dns_total,
        tls_total,
        http_total,
        hostnames_total,
        objects_total,
        certificates_total,
        ..PcapIndex::default()
    }
}

/// `_split_url`: urlsplit, or None for a URL that doesn't parse.
pub fn split_url(url: &str) -> Option<ace_pycompat::parse::SplitResult> {
    ace_pycompat::parse::urlsplit(url, "", true).ok()
}

/// `_link_http_objects`: an exported HTTP object is named after the last segment of its URL path;
/// it's linked to that URL when exactly one request in the table matches.
pub fn link_http_objects(index: &mut PcapIndex) {
    let mut by_name: HashMap<String, BTreeSet<String>> = HashMap::new();
    for request in &index.http {
        let Some(url) = request.url.as_deref().filter(|u| !u.is_empty()) else {
            continue;
        };
        let Some(parts) = split_url(url) else {
            continue;
        };
        let name = parts.path.rsplit('/').next().unwrap_or_default();
        if !name.is_empty() {
            by_name
                .entry(name.to_owned())
                .or_default()
                .insert(url.to_owned());
        }
    }
    for entry in &mut index.objects {
        if entry.protocol != "http" {
            continue;
        }
        let urls = by_name.get(&entry.file_name);
        entry.url = Some(match urls {
            Some(urls) if urls.len() == 1 => urls.iter().next().cloned(),
            _ => None,
        });
    }
}

/// `merge_index`: `new`, with every row of `previous` kept as it was: a later decryption adds rows
/// to the earlier one's tables and never replaces them.
pub fn merge_index(previous: Option<&PcapIndex>, new: PcapIndex, max_rows: usize) -> PcapIndex {
    let Some(previous) = previous else {
        return new;
    };
    fn merge<R: Clone>(
        old: &[R],
        old_total: u64,
        new: Vec<R>,
        new_total: u64,
        key: impl Fn(&R) -> String,
        objects: bool,
        max_rows: usize,
    ) -> (Vec<R>, u64) {
        let old_keys: BTreeSet<String> = old.iter().map(&key).collect();
        let mut rows: Vec<R> = old.to_vec();
        rows.extend(new.into_iter().filter(|r| !old_keys.contains(&key(r))));
        rows.truncate(max_rows);
        // a later run decrypts every earlier session again, so its tables already count the
        // earlier rows; only its objects leave out what was carved before (known_sha256)
        let total = if objects {
            old_total + new_total
        } else {
            old_total.max(new_total)
        };
        let total = total.max(rows.len() as u64);
        (rows, total)
    }
    let mut merged = new.clone();
    merged.carved_sha256 = previous
        .carved_sha256
        .iter()
        .chain(&new.carved_sha256)
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    (merged.dns, merged.dns_total) = merge(
        &previous.dns,
        previous.dns_total,
        new.dns,
        new.dns_total,
        |r| r.name.clone(),
        false,
        max_rows,
    );
    (merged.tls, merged.tls_total) = merge(
        &previous.tls,
        previous.tls_total,
        new.tls,
        new.tls_total,
        |r| r.flow.clone(),
        false,
        max_rows,
    );
    (merged.http, merged.http_total) = merge(
        &previous.http,
        previous.http_total,
        new.http,
        new.http_total,
        |r| format!("{:?}", (&r.method, &r.url)),
        false,
        max_rows,
    );
    (merged.hostnames, merged.hostnames_total) = merge(
        &previous.hostnames,
        previous.hostnames_total,
        new.hostnames,
        new.hostnames_total,
        |r| pystr::lower(&r.name).into_owned(),
        false,
        max_rows,
    );
    (merged.objects, merged.objects_total) = merge(
        &previous.objects,
        previous.objects_total,
        new.objects,
        new.objects_total,
        |r| r.sha256.clone(),
        true,
        max_rows,
    );
    (merged.certificates, merged.certificates_total) = merge(
        &previous.certificates,
        previous.certificates_total,
        new.certificates,
        new.certificates_total,
        |r| r.sha256.clone(),
        false,
        max_rows,
    );
    merged
}

/// The carved files a result stores for its root.
pub fn stored(files: &[NewFile]) -> Vec<StoredFile> {
    let mut stored: Vec<StoredFile> = Vec::new();
    for file in files {
        if !stored.iter().any(|s| s.sha256 == file.sha256) {
            stored.push(StoredFile::from(file));
        }
    }
    stored
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_taken_gets_the_first_free_number() {
        let mut used = BTreeSet::new();
        assert_eq!(unique_path(&mut used, "a/x.txt"), "a/x.txt");
        assert_eq!(unique_path(&mut used, "a/x.txt"), "a/x_000.txt");
        assert_eq!(unique_path(&mut used, "a/x.txt"), "a/x_001.txt");
        assert_eq!(splitext("a/.hidden"), ("a/.hidden", ""));
        assert_eq!(splitext("a.b/c.tar.gz"), ("a.b/c.tar", ".gz"));
        assert_eq!(splitext("a/b"), ("a/b", ""));
    }

    #[test]
    fn hex_is_read_as_bytes_fromhex_reads_it() {
        assert_eq!(from_hex("30 82"), Some(vec![0x30, 0x82]));
        assert_eq!(from_hex("3"), None);
        assert_eq!(from_hex("zz"), None);
    }

    #[test]
    fn a_certificate_that_does_not_parse_has_no_names() {
        assert_eq!(
            certificate_names(b"\x30\x82\x01\x00junk"),
            CertificateRow::default()
        );
    }

    fn layers(fields: &[(&str, &[&str])]) -> Layers {
        fields
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.iter().map(|s| (*s).to_owned()).collect()))
            .collect()
    }

    #[test]
    fn dns_rows_follow_names_answers_and_roles() {
        let packets = [
            layers(&[("frame.number", &["1"]), ("dns.qry.name", &["WWW.Example"])]),
            layers(&[
                ("frame.number", &["2"]),
                ("frame.time_epoch", &["10.5"]),
                ("dns.flags.response", &["True"]),
                ("dns.qry.name", &["www.example"]),
                ("dns.resp.name", &["www.example", "cdn.example", "<Root>"]),
                ("dns.resp.type", &["5", "1", "41"]),
                ("dns.cname", &["cdn.example"]),
                ("dns.a", &["192.0.2.1"]),
            ]),
            layers(&[("dns.qry.name", &["<Root>"])]),
        ];
        let index = build_index(&packets, Vec::new(), Vec::new(), 500);
        let names: Vec<&str> = index.dns.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["www.example", "cdn.example"]);
        assert_eq!(index.dns[0].queries, 1);
        assert_eq!(index.dns[0].responses, 1);
        assert_eq!(index.dns[0].answers, ["192.0.2.1", "cdn.example"]);
        assert_eq!(
            index.dns[0].answer_times.as_ref().unwrap()["192.0.2.1"],
            10.5
        );
        assert_eq!(index.dns[1].seen_as, ["cname"]);
        assert!(index.dns[1].answer_times.is_none());
    }
}
