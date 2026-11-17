//! The packet capture results' view (PLAN.md 7.5 batch 13), from ace3's `analysis/pcap_analysis.html`
//! and its `PcapAnalysisPresenter` (`saq/modules/file_analysis/pcap.py`): a line naming the capture,
//! a notice of what the page lacks, and the tables. ace3's cells that pivot to the alerts with an
//! observable are its text here: ace4's alert view links observables itself.

use askama::Template;
use chrono::{DateTime, Utc};

use ace_results::types::pcap::{
    Capture, CertificateRow, Counts, PcapAnalysis, PcapCategory, PcapDnsAnalysis,
    PcapFilesAnalysis, PcapHttpAnalysis, PcapIndex, PcapTlsAnalysis, PcapTlsDecryptionAnalysis,
    TlsKeylogAnalysis,
};

use super::AnalysisView;

/// One table of the page.
#[derive(Debug, Clone, PartialEq)]
pub struct PcapTable {
    pub title: &'static str,
    pub columns: Vec<&'static str>,
    pub rows: Vec<Vec<String>>,
    /// The table's whole count, when it was cut.
    pub total: u64,
    /// How its rows are ordered, and a note on what they are.
    pub order: Option<String>,
    pub note: Option<String>,
}

impl PcapTable {
    /// The rows shown are fewer than the table had.
    pub fn cut(&self) -> bool {
        self.total > self.rows.len() as u64
    }
}

/// A pcap result's page.
#[derive(Debug, Template)]
#[template(path = "analysis/pcap.html")]
pub struct PcapView {
    /// The parts of the line that says which capture the page is of.
    pub capture: Vec<String>,
    pub notice: Option<String>,
    pub tables: Vec<PcapTable>,
}

fn table(
    title: &'static str,
    columns: &[&'static str],
    rows: Vec<Vec<String>>,
    total: Option<u64>,
    order: Option<String>,
    note: Option<String>,
) -> PcapTable {
    let total = total.unwrap_or(rows.len() as u64);
    PcapTable {
        title,
        columns: columns.to_vec(),
        rows,
        total,
        order,
        note,
    }
}

const JA4_NOTE: &str = "JA4 fingerprints the client that started the session (its TLS ClientHello), not the server. \
    Every session from the same browser or application has the same JA4, whatever site it went to, \
    so one JA4 across many sites is normal. An unexpected JA4 points at an unusual client.";

/// `_capture_order`.
fn capture_order(what: &str, capture: Option<&Capture>) -> String {
    match capture.and_then(|c| c.strict_time_order) {
        Some(true) => format!("{what}, which is chronological."),
        Some(false) => format!(
            "{what}. The packets in this capture are not in time order, so this is not strictly chronological."
        ),
        None => format!("{what}."),
    }
}

/// `_packet_limit_note`.
fn packet_limit_note(limit: Option<u64>, capture: Option<&Capture>) -> Option<String> {
    let packets = capture.and_then(|c| c.packets)?;
    let limit = limit.filter(|l| *l > 0)?;
    (packets > limit).then(|| {
        format!(
            "Read from the first {} of the capture's {} packets only.",
            thousands(limit),
            thousands(packets)
        )
    })
}

fn notes(notes: &[Option<String>]) -> Option<String> {
    let joined = notes
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    (!joined.is_empty()).then_some(joined)
}

/// `{n:,}`.
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// `human_readable_size`: `'{:.4g} {}'` of the size in its binary order.
fn human_readable_size(size: u64) -> String {
    const SUFFIXES: [&str; 8] = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"];
    let order = if size == 0 {
        0
    } else {
        ((size as f64).log2() / 10.0) as usize
    };
    let value = size as f64 / (1u64 << (order * 10)) as f64;
    format!("{} {}", general_4(value), SUFFIXES[order.min(7)])
}

/// Python's `{:.4g}` for a value under 10,000.
fn general_4(value: f64) -> String {
    if value == 0.0 {
        return "0".to_owned();
    }
    let exponent = value.abs().log10().floor() as i32;
    let decimals = (3 - exponent).max(0) as usize;
    let text = format!("{value:.decimals$}");
    if text.contains('.') {
        text.trim_end_matches('0').trim_end_matches('.').to_owned()
    } else {
        text
    }
}

/// `_format_time_range`.
fn time_range(capture: &Capture) -> Option<String> {
    let (first, last) = (capture.first?, capture.last?);
    let at = |t: f64| DateTime::<Utc>::from_timestamp_micros((t * 1e6).round() as i64);
    let (first, last) = (at(first)?, at(last)?);
    let end = if last.date_naive() == first.date_naive() {
        last.format("%H:%M:%S").to_string()
    } else {
        last.format("%Y-%m-%d %H:%M:%S").to_string()
    };
    let length = match capture.duration {
        None => String::new(),
        Some(d) if d < 60.0 => format!(" ({d:.1} s)"),
        Some(d) => {
            let seconds = d.round() as u64;
            format!(
                " ({}:{:02}:{:02})",
                seconds / 3600,
                seconds / 60 % 60,
                seconds % 60
            )
        }
    };
    Some(format!(
        "{} to {end} UTC{length}",
        first.format("%Y-%m-%d %H:%M:%S")
    ))
}

/// `capture_summary`.
fn capture_summary(capture: Option<&Capture>) -> Vec<String> {
    let Some(capture) = capture else {
        return Vec::new();
    };
    let mut parts = vec![Some(capture.file_name.clone()), capture.format.clone()];
    parts.push(capture.size.map(human_readable_size));
    if !capture.encapsulations.is_empty() {
        let interfaces = capture.interfaces.unwrap_or(0);
        parts.push(Some(format!(
            "{}, {interfaces} interface{}",
            capture.encapsulations.join(", "),
            if interfaces == 1 { "" } else { "s" }
        )));
    }
    parts.push(capture.packets.map(|p| format!("{} packets", thousands(p))));
    parts.push(time_range(capture));
    if let Some(application) = &capture.application {
        // "Dumpcap (Wireshark) 4.4.19 (Git v4.4.19 packaged as ...)": the build details add nothing
        let application = match application.rfind(" (Git ") {
            Some(i) if application.ends_with(')') => &application[..i],
            _ => application.as_str(),
        };
        parts.push(Some(format!("written by {application}")));
    }
    parts
        .into_iter()
        .flatten()
        .filter(|p| !p.is_empty())
        .collect()
}

/// `describe_certificate`.
fn describe_certificate(entry: &CertificateRow) -> String {
    let Some(subject) = entry.subject.clone().flatten().filter(|s| !s.is_empty()) else {
        return format!(
            "certificate {}",
            &entry.sha256[..entry.sha256.len().min(16)]
        );
    };
    let mut text = subject.clone();
    let sans: Vec<String> = entry
        .sans
        .clone()
        .unwrap_or_default()
        .into_iter()
        .take(3)
        .collect();
    if !sans.is_empty() {
        let more = entry
            .san_total
            .unwrap_or(sans.len() as u64)
            .saturating_sub(sans.len() as u64);
        let more = if more > 0 {
            format!(", +{more} more")
        } else {
            String::new()
        };
        text.push_str(&format!(" (SAN: {}{more})", sans.join(", ")));
    }
    match entry.issuer.clone().flatten() {
        Some(issuer) if issuer != subject => {
            text.push_str(&format!(" \u{2014} issued by {issuer}"))
        }
        Some(_) => text.push_str(" \u{2014} self-signed"),
        None => {}
    }
    text
}

fn text(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

fn text2(value: &Option<Option<String>>) -> String {
    value.clone().flatten().unwrap_or_default()
}

/// `index_tables`: the tables of a category of an index, or all of them.
fn index_tables(
    index: &PcapIndex,
    category: Option<&str>,
    capture: Option<&Capture>,
) -> Vec<PcapTable> {
    let mut tables = Vec::new();
    let limit_note = packet_limit_note(Some(index.field_packet_limit), capture);
    let wants = |c: &str| category.is_none_or(|wanted| wanted == c);
    if wants("dns") && !index.dns.is_empty() {
        let rows = index
            .dns
            .iter()
            .map(|r| {
                vec![
                    r.name.clone(),
                    r.answers.join(", "),
                    r.queries.to_string(),
                    r.responses.to_string(),
                ]
            })
            .collect();
        tables.push(table(
            "DNS",
            &["Name", "Answers", "Queries", "Responses"],
            rows,
            Some(index.dns_total),
            Some(capture_order(
                "Names in the order they first appear in the capture",
                capture,
            )),
            limit_note.clone(),
        ));
    }
    if wants("tls") && !index.tls.is_empty() {
        let rows = index
            .tls
            .iter()
            .map(|r| {
                let certificates: Vec<String> = r
                    .certificates
                    .iter()
                    .map(|sha256| {
                        let entry = index
                            .certificates
                            .iter()
                            .find(|c| &c.sha256 == sha256)
                            .cloned()
                            .unwrap_or_else(|| CertificateRow {
                                sha256: sha256.clone(),
                                ..CertificateRow::default()
                            });
                        describe_certificate(&entry)
                    })
                    .collect();
                vec![
                    text2(&r.server),
                    text2(&r.sni),
                    text2(&r.ja4),
                    certificates.join("\n"),
                ]
            })
            .collect();
        tables.push(table(
            "TLS Sessions",
            &["Server", "SNI", "JA4", "Certificates"],
            rows,
            Some(index.tls_total),
            Some(capture_order(
                "Sessions in the order their handshakes start",
                capture,
            )),
            notes(&[Some(JA4_NOTE.to_owned()), limit_note.clone()]),
        ));
    }
    if wants("http") && !index.http.is_empty() {
        let rows = index
            .http
            .iter()
            .map(|r| {
                vec![
                    text(&r.method),
                    text(&r.url),
                    text(&r.status),
                    text(&r.content_type),
                    text(&r.user_agent),
                ]
            })
            .collect();
        tables.push(table(
            "HTTP Requests",
            &["Method", "URL", "Status", "Content Type", "User Agent"],
            rows,
            Some(index.http_total),
            Some(capture_order(
                "Requests in the order they were sent",
                capture,
            )),
            limit_note.clone(),
        ));
    }
    if wants("files") && !index.objects.is_empty() {
        let rows = index
            .objects
            .iter()
            .map(|r| {
                vec![
                    r.protocol.clone(),
                    r.file_name.clone(),
                    r.size.to_string(),
                    r.sha256.clone(),
                    text2(&r.url),
                ]
            })
            .collect();
        tables.push(table(
            "Carved Files",
            &["Protocol", "File Name", "Size", "SHA256", "URL"],
            rows,
            Some(index.objects_total),
            // tshark's object export does not say when each object crossed the wire
            Some("By protocol, then file name. Not chronological.".to_owned()),
            None,
        ));
    }
    tables
}

fn format_counts(counts: &Counts) -> String {
    counts
        .iter()
        .map(|(kind, count)| format!("{count} {kind}"))
        .collect::<Vec<_>>()
        .join(", ")
}

impl AnalysisView for PcapAnalysis {
    type View<'a> = PcapView;
    fn view(&self) -> PcapView {
        let Some(index) = &self.index else {
            return PcapView {
                capture: Vec::new(),
                notice: None,
                tables: Vec::new(),
            };
        };
        let capture = index.capture.clone().flatten();
        let capture = capture.as_ref();
        let statistics = index.statistics.clone().unwrap_or_default();
        let mut tables = Vec::new();
        if let Some(embedded) = &index.embedded_secrets {
            let mut rows: Vec<Vec<String>> = embedded
                .types
                .iter()
                .map(|(name, count)| vec![format!("{name} secrets blocks"), count.to_string()])
                .collect();
            rows.extend(
                embedded
                    .label_counts
                    .iter()
                    .map(|(label, count)| vec![format!("TLS {label}"), count.to_string()]),
            );
            rows.push(vec![
                "TLS sessions with keys".to_owned(),
                embedded.keyed_client_randoms.len().to_string(),
            ]);
            tables.push(table(
                "Embedded Decryption Secrets",
                &["Secret", "Count"],
                rows,
                None,
                None,
                None,
            ));
        }
        if !index.hostnames.is_empty() {
            let rows = index
                .hostnames
                .iter()
                .map(|r| vec![r.name.clone(), r.source.clone(), text(&r.mac)])
                .collect();
            tables.push(table(
                "Hostnames",
                &["Name", "Source", "MAC"],
                rows,
                Some(index.hostnames_total),
                Some(capture_order(
                    "In the order they first appear in the capture",
                    capture,
                )),
                packet_limit_note(Some(index.field_packet_limit), capture),
            ));
        }
        for (title, rows, total) in [
            ("IP Endpoints", statistics.ip.clone(), statistics.ip_total),
            (
                "Ethernet Endpoints",
                statistics.mac.clone(),
                statistics.mac_total,
            ),
        ] {
            let rows = rows.unwrap_or_default();
            if !rows.is_empty() {
                let rows = rows
                    .iter()
                    .map(|r| {
                        vec![
                            r.address.clone(),
                            r.packets.to_string(),
                            r.bytes.to_string(),
                        ]
                    })
                    .collect();
                tables.push(table(
                    title,
                    &["Address", "Packets", "Bytes"],
                    rows,
                    total,
                    Some("Most packets first.".to_owned()),
                    None,
                ));
            }
        }
        let flows = statistics.flows.clone().unwrap_or_default();
        if !flows.is_empty() {
            let rows = flows
                .iter()
                .map(|r| {
                    vec![
                        r.protocol.clone(),
                        r.a.clone(),
                        r.b.clone(),
                        r.frames.to_string(),
                        r.bytes.clone(),
                        r.start.to_string(),
                        r.duration.to_string(),
                    ]
                })
                .collect();
            tables.push(table(
                "Flows",
                &["Protocol", "A", "B", "Frames", "Bytes", "Start", "Duration"],
                rows,
                statistics.flows_total,
                Some("Most frames first. Start is seconds after the first packet.".to_owned()),
                None,
            ));
        }
        let notice = index.statistics_error.clone().flatten().map(|e| {
            format!("No endpoint or flow tables: the packet statistics pass failed ({e}).")
        });
        PcapView {
            capture: capture_summary(capture),
            notice,
            tables,
        }
    }
}

/// A category's page: its table, from the rows and count it copied.
fn category_view(
    category: &str,
    capture: Option<&Capture>,
    field_packet_limit: Option<u64>,
    index: PcapIndex,
) -> PcapView {
    let index = PcapIndex {
        field_packet_limit: field_packet_limit.unwrap_or(0),
        ..index
    };
    PcapView {
        capture: capture_summary(capture),
        notice: None,
        tables: index_tables(&index, Some(category), capture),
    }
}

fn base<R>(details: &PcapCategory<R>) -> (Option<&Capture>, Option<u64>) {
    (details.capture.as_ref(), details.field_packet_limit)
}

impl AnalysisView for PcapDnsAnalysis {
    type View<'a> = PcapView;
    fn view(&self) -> PcapView {
        let (capture, limit) = base(&self.0);
        let index = PcapIndex {
            dns: self.0.rows.clone(),
            dns_total: self.0.total,
            ..PcapIndex::default()
        };
        category_view("dns", capture, limit, index)
    }
}

impl AnalysisView for PcapTlsAnalysis {
    type View<'a> = PcapView;
    fn view(&self) -> PcapView {
        let (capture, limit) = base(&self.0);
        let index = PcapIndex {
            tls: self.0.rows.clone(),
            tls_total: self.0.total,
            certificates: self.0.certificates.clone().unwrap_or_default(),
            ..PcapIndex::default()
        };
        category_view("tls", capture, limit, index)
    }
}

impl AnalysisView for PcapHttpAnalysis {
    type View<'a> = PcapView;
    fn view(&self) -> PcapView {
        let (capture, limit) = base(&self.0);
        let index = PcapIndex {
            http: self.0.rows.clone(),
            http_total: self.0.total,
            ..PcapIndex::default()
        };
        category_view("http", capture, limit, index)
    }
}

impl AnalysisView for PcapFilesAnalysis {
    type View<'a> = PcapView;
    fn view(&self) -> PcapView {
        let (capture, limit) = base(&self.0);
        let index = PcapIndex {
            objects: self.0.rows.clone(),
            objects_total: self.0.total,
            ..PcapIndex::default()
        };
        category_view("files", capture, limit, index)
    }
}

impl AnalysisView for PcapTlsDecryptionAnalysis {
    type View<'a> = PcapView;
    fn view(&self) -> PcapView {
        let capture = self.capture.clone().flatten();
        let mut rows = Vec::new();
        if let Some(embedded) = self.sessions_with_embedded_keys.filter(|n| *n > 0) {
            rows.push(vec![
                "(embedded in the capture)".to_owned(),
                String::new(),
                format!("keys for {embedded} TLS sessions"),
            ]);
        }
        rows.extend(self.keylogs.iter().map(|k| {
            vec![
                k.file_name.clone(),
                k.sha256.clone(),
                format_counts(&k.label_counts),
            ]
        }));
        let mut tables = Vec::new();
        if !rows.is_empty() {
            tables.push(table(
                "Key Sources",
                &["Source", "SHA256", "Secrets"],
                rows,
                None,
                None,
                None,
            ));
        }
        if let Some(index) = &self.index {
            tables.extend(index_tables(index, None, capture.as_ref()));
        }
        PcapView {
            capture: capture_summary(capture.as_ref()),
            notice: None,
            tables,
        }
    }
}

impl AnalysisView for TlsKeylogAnalysis {
    type View<'a> = PcapView;
    fn view(&self) -> PcapView {
        let rows = self
            .label_counts
            .iter()
            .map(|(label, count)| vec![label.clone(), count.to_string()])
            .collect();
        PcapView {
            capture: Vec::new(),
            notice: None,
            tables: vec![table(
                "Secrets",
                &["Label", "Count"],
                rows,
                None,
                None,
                None,
            )],
        }
    }
}
