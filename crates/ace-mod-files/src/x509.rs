//! `x509_analyzer`: ace3's `X509Analyzer` (`saq/modules/x509.py`), on `ace-x509`, which does what
//! ace3's `saq/x509.py` does with cryptography and pyasn1. Also the certificate check
//! `file_type` makes.
//!
//! For a file file_type calls a certificate: its issuer, subject, dates, serial, common name,
//! subject alternative names, hash and extensions, with the names as fqdn observables and, unless
//! the file has `no_crawl`, as http and https URLs to crawl, the SAN addresses as ip observables,
//! the certificate's SHA-256, and the details written to `<file's sha256>.metadata` with the
//! `yara_meta` type `metadata.x509`.
//!
//! Where ace4 departs:
//!
//! - ace3 doesn't crawl a certificate's names when the file came from a URL observable (one of
//!   its parents). A task doesn't carry its observable's parents, and no ported module adds a
//!   file under a URL yet (the crawlers are 7.7's), so only `no_crawl` stops the URLs.
//! - A serial number past 64 bits is its decimal text, where ace3 writes a JSON number.
//! - `is_x509` raises in ace3 for a certificate of a version cryptography doesn't know, which fails
//!   ace3's whole file_type analysis of the file. Here it's not a certificate, and file_type's
//!   other checks still land.

use ace_results::FileRole;
use ace_results::types::file_type::FileTypeAnalysis;
use ace_results::types::x509::{SerialNumber, SubjectAlternativeNames, X509Analysis};
use ace_results::{AnalysisType, NewObservable, ObservableKind, ResultEnvelope};
use ace_sdk::takes::{Condition, Takes};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<X509Analyzer>();

const DIRECTIVE_CRAWL: &str = "crawl";
const DIRECTIVE_NO_CRAWL: &str = "no_crawl";
/// With `no_crawl`, at most this many SAN names become fqdn observables.
const MAX_NO_CRAWL_SAN_FQDNS: usize = 10;

/// `is_x509`: a PEM or DER certificate cryptography loads.
pub fn is_x509(data: &[u8]) -> bool {
    ace_x509::is_x509(data).unwrap_or(false)
}

pub struct X509Analyzer;

impl Module for X509Analyzer {
    const NAME: &'static str = X509Analysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const DEPENDS_ON: &'static [&'static str] = &[FileTypeAnalysis::MODULE];
    type Output = X509Analysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(X509Analyzer)
    }

    fn takes(_: &()) -> Takes {
        Takes::everything()
            .and(
                Condition::HasResult(FileTypeAnalysis::MODULE.to_owned()),
                "no file type analysis",
            )
            .and(
                Condition::result_true(FileTypeAnalysis::MODULE, "is_x509"),
                "not an x509 certificate",
            )
    }
}

/// `remove_wildcard`.
fn remove_wildcard(name: &str) -> &str {
    name.strip_prefix("*.").unwrap_or(name)
}

/// `saq.util.strings.format_item_list_for_summary`, with its 20 items.
fn item_list(items: &[String]) -> String {
    let mut result = items[..items.len().min(20)].join(", ");
    if items.len() > 20 {
        result.push_str(&format!(" + {} more", items.len() - 20));
    }
    result
}

fn named(kind: ObservableKind, value: &str, display: &str, crawl: bool) -> NewObservable {
    let mut observable = NewObservable::new(kind, value);
    observable.display_type = Some(display.to_owned());
    if crawl {
        observable.directives.push(DIRECTIVE_CRAWL.to_owned());
    }
    observable
}

impl Parser for X509Analyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<X509Analysis>, ModuleError> {
        let file = ctx.input_file()?;
        let data = std::fs::read(&file.local_path)?;
        let cert = ace_x509::load_cert(&data)
            .map_err(|e| ModuleError::other(e.to_string()))?
            .ok_or_else(|| ModuleError::other("the certificate doesn't load"))?;
        let details = ace_x509::analyze(&cert).map_err(|e| ModuleError::other(e.to_string()))?;

        let no_crawl = ctx.observable().has_directive(DIRECTIVE_NO_CRAWL);
        let crawl = !no_crawl;
        let mut observables = Vec::new();
        if let Some(common_name) = &details.common_name {
            let name = remove_wildcard(common_name);
            observables.push(named(
                ObservableKind::Fqdn,
                name,
                "Certificate Common Name",
                false,
            ));
            if crawl {
                observables.push(named(
                    ObservableKind::Url,
                    &format!("http://{name}"),
                    "Certificate Common Name URL (http)",
                    true,
                ));
                observables.push(named(
                    ObservableKind::Url,
                    &format!("https://{name}"),
                    "Certificate Common Name URL (https)",
                    true,
                ));
            }
        }
        for address in &details.san_ip_addresses {
            observables.push(named(
                ObservableKind::Ip,
                address,
                "Certificate SAN IP Address",
                false,
            ));
        }
        for (index, dns_name) in details.san_dns_names.iter().enumerate() {
            if no_crawl && index >= MAX_NO_CRAWL_SAN_FQDNS {
                continue;
            }
            let name = remove_wildcard(dns_name);
            observables.push(named(
                ObservableKind::Fqdn,
                name,
                "Certificate SAN DNS Name",
                false,
            ));
            if crawl {
                observables.push(named(
                    ObservableKind::Url,
                    &format!("http://{name}"),
                    "Certificate SAN URL (http)",
                    true,
                ));
                observables.push(named(
                    ObservableKind::Url,
                    &format!("https://{name}"),
                    "Certificate SAN URL (https)",
                    true,
                ));
            }
        }
        observables.push(NewObservable::new(
            ObservableKind::Sha256,
            &details.sha256_hash,
        ));

        let not_valid_before = details.not_valid_before.utc_str();
        let summary = format!(
            "X509 Analysis: {} | Issuer={} | NotValidBefore={not_valid_before} | Subject Alternative Names: {} DNS Names, {} IP Addresses",
            details.common_name.as_deref().unwrap_or("None"),
            details.issuer,
            item_list(&details.san_dns_names),
            item_list(&details.san_ip_addresses),
        );
        let serial_number = match details.serial_number.parse::<i64>() {
            Ok(number) => SerialNumber::Number(number),
            Err(_) => SerialNumber::Text(details.serial_number.clone()),
        };
        let metadata = details.metadata_json();
        let analysis = X509Analysis {
            issuer: Some(details.issuer),
            subject: Some(details.subject),
            not_valid_before: Some(details.not_valid_before.utc_strftime()),
            not_valid_after: Some(details.not_valid_after.utc_strftime()),
            serial_number: Some(serial_number),
            common_name: details.common_name,
            sha256_hash: Some(details.sha256_hash),
            extensions: details.extensions,
            subject_alternative_names: SubjectAlternativeNames {
                san_ip_addresses: details.san_ip_addresses,
                san_dns_names: details.san_dns_names,
            },
        };
        let mut result = ResultEnvelope::new(analysis).with_summary(summary);
        result.observables = observables;
        let path = format!("{}.metadata", file.sha256.to_hex());
        result
            .files
            .push(ctx.write_file(&path, metadata.as_bytes(), FileRole::METADATA_X509)?);
        Ok(Outcome::Done(result))
    }
}
