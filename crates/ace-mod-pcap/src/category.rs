//! ace3's `PcapCategoryAnalyzer`, which its configuration runs as four instances, `pcap_dns`,
//! `pcap_tls`, `pcap_http` and `pcap_files`: one category of pcap_analyzer's index as observables,
//! under a result of its own. Here each is a module, by `Category`.

use std::marker::PhantomData;
use std::time::Duration;

use ace_results::types::pcap::{
    PcapAnalysis, PcapCategory, PcapDnsAnalysis, PcapFilesAnalysis, PcapHttpAnalysis, PcapIndex,
    PcapTlsAnalysis,
};
use ace_results::{AnalysisType, ObservableKind, ResultEnvelope};
use ace_sdk::{Module, ModuleError, Outcome, Parser, Resources, TaskContext};

use crate::budget::{CaptureFile, PcapSettings, category_rows, shares};
use crate::index::{CATEGORY_DNS, CATEGORY_FILES, CATEGORY_HTTP, CATEGORY_TLS};
use crate::{format_counts, is_pcap_file};

/// One of the four instances.
pub trait Category: Send + Sync + 'static {
    const NAME: &'static str;
    const CATEGORY: &'static str;
    /// `CATEGORY_TITLES`'s.
    const TITLE: &'static str;
    /// pcap_files and pcap_tls add files pcap_analyzer stored.
    const ADDS_STORED_FILES: bool;
    type Output: AnalysisType;
    /// The category's details, with its rows from the index.
    fn details(index: &PcapIndex, details: PcapCategory<()>) -> Self::Output;
}

/// The category's details but its rows.
fn base(index: &PcapIndex, category: &str, total: u64) -> PcapCategory<()> {
    PcapCategory {
        category: category.to_owned(),
        capture: index.capture.clone().flatten(),
        field_packet_limit: Some(index.field_packet_limit),
        rows: Vec::new(),
        total,
        certificates: None,
        added: Default::default(),
        omitted: Default::default(),
    }
}

fn with_rows<R>(details: PcapCategory<()>, rows: Vec<R>) -> PcapCategory<R> {
    PcapCategory {
        category: details.category,
        capture: details.capture,
        field_packet_limit: details.field_packet_limit,
        rows,
        total: details.total,
        certificates: details.certificates,
        added: details.added,
        omitted: details.omitted,
    }
}

/// pcap_dns: the names DNS saw.
pub struct Dns;
/// pcap_tls: the TLS sessions, their SNI and JA4, and the certificates.
pub struct Tls;
/// pcap_http: the HTTP requests, their hosts and user agents.
pub struct Http;
/// pcap_files: the objects tshark exported.
pub struct Files;

impl Category for Dns {
    const NAME: &'static str = "pcap_dns";
    const CATEGORY: &'static str = CATEGORY_DNS;
    const TITLE: &'static str = "DNS";
    const ADDS_STORED_FILES: bool = false;
    type Output = PcapDnsAnalysis;
    fn details(index: &PcapIndex, details: PcapCategory<()>) -> PcapDnsAnalysis {
        PcapDnsAnalysis(with_rows(details, index.dns.clone()))
    }
}

impl Category for Tls {
    const NAME: &'static str = "pcap_tls";
    const CATEGORY: &'static str = CATEGORY_TLS;
    const TITLE: &'static str = "TLS";
    const ADDS_STORED_FILES: bool = true;
    type Output = PcapTlsAnalysis;
    fn details(index: &PcapIndex, mut details: PcapCategory<()>) -> PcapTlsAnalysis {
        details.certificates = Some(index.certificates.clone());
        PcapTlsAnalysis(with_rows(details, index.tls.clone()))
    }
}

impl Category for Http {
    const NAME: &'static str = "pcap_http";
    const CATEGORY: &'static str = CATEGORY_HTTP;
    const TITLE: &'static str = "HTTP";
    const ADDS_STORED_FILES: bool = false;
    type Output = PcapHttpAnalysis;
    fn details(index: &PcapIndex, details: PcapCategory<()>) -> PcapHttpAnalysis {
        PcapHttpAnalysis(with_rows(details, index.http.clone()))
    }
}

impl Category for Files {
    const NAME: &'static str = "pcap_files";
    const CATEGORY: &'static str = CATEGORY_FILES;
    const TITLE: &'static str = "Files";
    const ADDS_STORED_FILES: bool = true;
    type Output = PcapFilesAnalysis;
    fn details(index: &PcapIndex, details: PcapCategory<()>) -> PcapFilesAnalysis {
        PcapFilesAnalysis(with_rows(details, index.objects.clone()))
    }
}

/// A category's module.
pub struct PcapCategoryAnalyzer<C>(PhantomData<C>);

pub type PcapDns = PcapCategoryAnalyzer<Dns>;
pub type PcapTls = PcapCategoryAnalyzer<Tls>;
pub type PcapHttp = PcapCategoryAnalyzer<Http>;
pub type PcapFiles = PcapCategoryAnalyzer<Files>;

impl<C: Category> Module for PcapCategoryAnalyzer<C> {
    const NAME: &'static str = C::NAME;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const DEPENDS_ON: &'static [&'static str] = &[PcapAnalysis::MODULE];
    const ADDS_STORED_FILES: bool = C::ADDS_STORED_FILES;
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        memory_mb: 1024,
        cpu_seconds: 60,
    };
    type Output = C::Output;
    type Settings = PcapSettings;

    fn init(_: &PcapSettings) -> Result<Self, ModuleError> {
        Ok(PcapCategoryAnalyzer(PhantomData))
    }
}

impl<C: Category> Parser for PcapCategoryAnalyzer<C> {
    fn analyze(&self, ctx: &TaskContext<PcapSettings>) -> Result<Outcome<C::Output>, ModuleError> {
        let file = ctx.input_file()?;
        if !file.local_path.is_file() || !is_pcap_file(&file.local_path) {
            return Ok(Outcome::Skipped("not a pcap or pcapng file".to_owned()));
        }
        // pcap_analyzer produced nothing, or the dissection failed and its result says so
        let Some(PcapAnalysis {
            index: Some(index), ..
        }) = ctx
            .dependency_result::<PcapAnalysis>()?
            .filter(|_| ctx.dependency_error::<PcapAnalysis>().is_none())
        else {
            return Ok(Outcome::Skipped(
                "pcap_analyzer has no index of the capture".to_owned(),
            ));
        };
        let alert_path = file.path.to_string();
        let capture = CaptureFile {
            sha256: &file.sha256.to_hex(),
            path: &alert_path,
        };
        let shares = shares(
            &capture,
            &index,
            &ctx.settings().categories,
            Some(C::CATEGORY),
        );
        let node = shares.category(C::CATEGORY);
        let rows = category_rows(&index, C::CATEGORY);
        // nothing in the capture for this category: no result
        if node.added.is_empty() && node.omitted.is_empty() && rows == 0 {
            return Ok(Outcome::Skipped(format!(
                "the capture has no {}",
                C::CATEGORY
            )));
        }
        let total = match C::CATEGORY {
            CATEGORY_DNS => index.dns_total,
            CATEGORY_TLS => index.tls_total,
            CATEGORY_HTTP => index.http_total,
            _ => index.objects_total,
        };
        let mut details = base(&index, C::CATEGORY, total);
        details.added = node.added.clone();
        details.omitted = node.omitted.clone();
        let summary = summary(C::TITLE, C::CATEGORY, &details);
        let mut result = ResultEnvelope::new(C::details(&index, details));
        result.observables = node.new_observables.clone();
        result.files = node.new_files.clone();
        result.summary = Some(summary);
        Ok(Outcome::Done(result))
    }
}

/// `PcapCategoryAnalysis.generate_summary`.
fn summary(title: &str, category: &str, details: &PcapCategory<()>) -> String {
    let what = if category == CATEGORY_FILES {
        "files"
    } else {
        "entries"
    };
    let mut summary = format!("PCAP {title}: {} {what}", details.total);
    if !details.added.is_empty() {
        summary.push_str(&format!(" ({})", format_counts(&details.added)));
    }
    if !details.omitted.is_empty() {
        let over: u64 = details.omitted.values().sum();
        summary.push_str(&format!(", {over} over the limit"));
    }
    summary
}
