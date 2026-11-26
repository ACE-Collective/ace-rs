//! `url_extraction`: ace3's `URLExtractionAnalyzer` (`saq/modules/file_analysis/url_extraction.py`).
//!
//! For a file with the `extract_urls` directive, urlfinderlib's URLs (`ace-urlfinder`), less those
//! of the excluded domains, ordered by interest: the URLs of the domains with the fewest URLs
//! first, images last. All of them go in the details, and the first `max_extracted_urls` become
//! URL observables, with `crawl` when the file has `crawl_extracted_urls`.
//!
//! As in ace3, it waits for `file_type`, whose result it reads, and for `yara_scanner_v3_4`, so the
//! directives a rule adds (`extract_urls_domain_as_url`, `crawl_extracted_urls`) are on the file
//! before it runs. A file no rule matched gets no YARA result, and the module runs once YARA won't
//! store one (PLAN.md decision 30).
//!
//! Where ace-rs departs:
//!
//! - urlfinderlib returns a set, and ace3 orders its URLs from that set's order, which changes with
//!   each process's hash seed; where two domains have as many URLs, which comes first changes from
//!   run to run. Here the set is sorted first, so the order is the same each time.
//! - ace3 adds the URLs as volatile observables. ace-rs has no volatile flag; in ace3 only the GUI's
//!   pruning and the analysis cache read it.
//! - urlfinderlib chooses its finder from libmagic's description of the bytes, which ace3's asks
//!   python-magic's `from_buffer` for. Here it is given the type step's description, from the
//!   file_type result (`file -b -L`'s flags, stripped), so a task loads no libmagic and
//!   makes no libmagic call for a description the type step has made already (PLAN.md decision 25).
//!   The two descriptions can differ: over 875 files (`samples/` and `tools/ace3/dumps/fixtures`)
//!   they differed on 28, 25 zips and 2 jars that `from_buffer` calls only "data" and a gzip whose
//!   size detail it leaves out. urlfinderlib's choice reads only whether the description holds
//!   "utf-16", "rfc 822", "mail", "html", "vcalendar", "icalendar", "xml" or "text", and none of
//!   the 28 hold one on either side, so every one of the 875 takes the same finder
//!   (`tests/type_description.rs` keeps a file of each class). libmagic is still loaded where
//!   urlfinderlib describes bytes the type step never saw: UTF-16 text with its NULs taken out,
//!   and a file whose description is empty. For those libmagic loads from the database's mapping,
//!   which `init` made, since a contained task can't open it.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use ace_pycompat::pystr;
use ace_results::types::file_type::FileTypeAnalysis;
use ace_results::types::url_extraction::UrlExtractionAnalysis;
use ace_results::types::yara::YaraScanResults;
use ace_results::{AnalysisType, NewObservable, ObservableKind, RelationshipKind, ResultEnvelope};
use ace_sdk::observable_rules::names_a_host;
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use ace_urlfinder::{Finder, magic};
use schemars::JsonSchema;
use serde::Deserialize;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<UrlExtraction>();

const DIRECTIVE_EXTRACT_URLS: &str = "extract_urls";
const DIRECTIVE_EXTRACT_URLS_DOMAIN_AS_URL: &str = "extract_urls_domain_as_url";
const DIRECTIVE_CRAWL_EXTRACTED_URLS: &str = "crawl_extracted_urls";
const DIRECTIVE_CRAWL: &str = "crawl";
/// `YARA_META_TYPE_OCR`, from ace3's OCR module.
const OCR_TEXT: &str = "document.text.ocr";
const IMAGE_EXTENSIONS: [&str; 6] = [".png", ".gif", ".jpeg", ".jpg", ".tiff", ".bmp"];

/// ace3's `analysis_module_url_extraction` settings.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct UrlExtractionSettings {
    /// The largest file to read, in megabytes.
    pub max_file_size: u64,
    /// How many of the URLs become observables.
    pub max_extracted_urls: usize,
    /// Hosts whose URLs, and their subdomains', are left out, such as XML schema hosts.
    pub excluded_domains: Vec<String>,
}

impl Default for UrlExtractionSettings {
    fn default() -> Self {
        UrlExtractionSettings {
            max_file_size: 10,
            max_extracted_urls: 12,
            excluded_domains: [
                "schemas.openxmlformats.org",
                "schemas.microsoft.com",
                "www.w3.org",
                "purl.org",
                "schemas.xmlsoap.org",
                "ns.adobe.com",
            ]
            .map(str::to_owned)
            .to_vec(),
        }
    }
}

/// The module, with libmagic's database mapped before containment, which can't open it. libmagic
/// is loaded only for a task whose bytes urlfinderlib has to describe itself.
pub struct UrlExtraction {
    database: magic::Database,
}

impl UrlExtraction {
    /// The module with libmagic's database at `path`; `init`'s is where the images keep it.
    pub fn with_database(path: &Path) -> UrlExtraction {
        UrlExtraction {
            database: magic::Database::open(path),
        }
    }
}

impl Module for UrlExtraction {
    const NAME: &'static str = UrlExtractionAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const REQUIRED_DIRECTIVES: &'static [&'static str] = &[DIRECTIVE_EXTRACT_URLS];
    const DEPENDS_ON: &'static [&'static str] =
        &[FileTypeAnalysis::MODULE, YaraScanResults::MODULE];
    // ace3's maximum_analysis_time, 15 s. docs/measurements/url-extraction.md has what a crafted file
    // costs.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(15),
        memory_mb: 2048,
        cpu_seconds: 15,
    };
    type Output = UrlExtractionAnalysis;
    type Settings = UrlExtractionSettings;

    fn init(_: &UrlExtractionSettings) -> Result<Self, ModuleError> {
        Ok(UrlExtraction::with_database(Path::new(
            ace_urlfinder::magic::DATABASE,
        )))
    }
}

/// `saq.util.networking.is_subdomain(src, dst)`: src is dst or below it.
pub fn is_subdomain(src: &str, dst: &str) -> bool {
    let src = pystr::lower(src);
    let dst = pystr::lower(dst);
    let src: Vec<&str> = src.split('.').rev().collect();
    let dst: Vec<&str> = dst.split('.').rev().collect();
    dst.iter()
        .enumerate()
        .all(|(i, part)| src.get(i) == Some(part))
}

impl UrlExtraction {
    /// `filter_excluded_domains`: False for a URL to leave out.
    fn kept(&self, settings: &UrlExtractionSettings, url: &str) -> bool {
        let fqdns: Vec<&str> = settings
            .excluded_domains
            .iter()
            .map(|d| pystr::strip(d))
            .collect();
        if fqdns.is_empty() {
            return true;
        }
        let Ok(parsed) = ace_pycompat::parse::urlparse(url, "", true) else {
            return true;
        };
        let Some(hostname) = parsed.hostname() else {
            return true;
        };
        if !hostname.contains('.') {
            return false;
        }
        !fqdns.iter().any(|fqdn| is_subdomain(&hostname, fqdn))
    }
}

/// `order_urls_by_interest`: by how few URLs their domain has, images last, and the URLs by
/// domain.
pub fn order_urls_by_interest(urls: &[String]) -> (Vec<String>, Vec<(String, Vec<String>)>) {
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    let mut images: Vec<&String> = Vec::new();
    let add = |groups: &mut Vec<(String, Vec<String>)>, key: String, url: &String| match groups
        .iter_mut()
        .find(|(k, _)| *k == key)
    {
        Some((_, list)) => list.push(url.clone()),
        None => groups.push((key, vec![url.clone()])),
    };
    for url in urls {
        match ace_pycompat::tld::get_tld_object(url, false, false, true, true) {
            Ok(Some(found)) => {
                let domain = format!("{}.{}", found.domain, found.tld);
                add(&mut groups, domain, url);
                if IMAGE_EXTENSIONS
                    .iter()
                    .any(|ext| found.parsed_url.path.ends_with(ext))
                {
                    images.push(url);
                }
            }
            _ => add(&mut groups, "no_tld".to_owned(), url),
        }
    }
    let mut ordered_domains: Vec<&(String, Vec<String>)> = groups.iter().collect();
    ordered_domains.sort_by_key(|(_, list)| list.len());
    let mut ordered = Vec::with_capacity(urls.len());
    for (_, list) in ordered_domains {
        for url in list {
            if !images.contains(&url) {
                ordered.push(url.clone());
            }
        }
    }
    ordered.extend(images.into_iter().cloned());
    (ordered, groups)
}

/// `generate_summary`: the hosts, sorted, at most 20 named.
fn summary(urls: &[String]) -> Option<String> {
    if urls.is_empty() {
        return None;
    }
    let mut domains: BTreeSet<String> = BTreeSet::new();
    for url in urls {
        if let Ok(parsed) = ace_pycompat::parse::urlparse(url, "", true)
            && let Some(host) = parsed.hostname()
        {
            domains.insert(host);
        }
    }
    let domains: Vec<String> = domains.into_iter().collect();
    Some(format!(
        "URL Extraction Analysis ({})",
        format_item_list_for_summary(&domains, 20)
    ))
}

/// `saq.util.strings.format_item_list_for_summary`.
pub fn format_item_list_for_summary(items: &[String], max_items: usize) -> String {
    let mut result = items[..items.len().min(max_items)].join(", ");
    if items.len() > max_items {
        result.push_str(&format!(" + {} more", items.len() - max_items));
    }
    result
}

impl Parser for UrlExtraction {
    fn analyze(
        &self,
        ctx: &TaskContext<UrlExtractionSettings>,
    ) -> Result<Outcome<UrlExtractionAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let settings = ctx.settings();
        // ace3 returns without an analysis when file_type has none
        let Some(file_type) = ctx.dependency_result::<FileTypeAnalysis>()? else {
            return Ok(Outcome::Skipped("no file type analysis".to_owned()));
        };
        if file.size == 0 {
            return Ok(Outcome::Skipped("an empty file".to_owned()));
        }
        if file.size > settings.max_file_size * 1024 * 1024 {
            return Ok(Outcome::Skipped(
                "too large to extract URLs from".to_owned(),
            ));
        }
        let has_type = |value: &str| {
            file.yara_meta
                .iter()
                .any(|m| m.name() == "type" && m.value() == value)
        };
        // the type step's description of the bytes, which urlfinderlib would otherwise ask libmagic
        // for; an empty one still has urlfinderlib ask
        let url_mimetype = if has_type("script.javascript") {
            "text/plain"
        } else {
            file_type.file_type.as_str()
        };
        let domain_as_url = ctx
            .observable()
            .has_directive(DIRECTIVE_EXTRACT_URLS_DOMAIN_AS_URL);
        let blob = fs::read(&file.local_path)?;
        ctx.check_cancelled()?;

        let ocr = has_type(OCR_TEXT);
        let load_magic = || self.database.load();
        let finder = Finder::on_demand(&load_magic);
        let found = if ocr {
            ace_urlfinder::find_urls_in_text(&blob, domain_as_url)
        } else {
            // an HTML file downloaded from a URL has its relative URLs made absolute against it
            let base_url = if pystr::lower(&file_type.mime).contains("html") {
                ctx.observable()
                    .relationship(RelationshipKind::DownloadedFrom)
                    .map_or("", |r| r.target.value.as_str())
            } else {
                ""
            };
            finder.find_urls(&blob, base_url, url_mimetype, domain_as_url)
        };
        let mut extracted: Vec<String> = match found {
            Ok(urls) => urls.into_iter().collect(),
            Err(e) => {
                // a module that can't load libmagic fails every such task, which the file didn't
                // cause, so it fails the task rather than skipping the file
                if let Some(why) = finder.load_error() {
                    return Err(ModuleError::other(why.to_owned()));
                }
                tracing::warn!("failed to extract urls from {}: {e}", file.path.as_str());
                return Ok(Outcome::Skipped(format!("failed to extract urls: {e}")));
            }
        };

        // OCR text is a guess: keep only what's a URL as written
        if ocr {
            extracted.retain(|url| ace_pycompat::validators::url(url, true));
        }
        extracted.retain(|url| self.kept(settings, url));

        let (ordered, groups) = order_urls_by_interest(&extracted);
        let crawl = ctx
            .observable()
            .has_directive(DIRECTIVE_CRAWL_EXTRACTED_URLS);
        let mut observables = Vec::new();
        for url in &ordered {
            if observables.len() < settings.max_extracted_urls && names_a_host(url) {
                let mut observable = NewObservable::new(ObservableKind::Url, url.clone());
                if crawl {
                    observable.directives.push(DIRECTIVE_CRAWL.to_owned());
                }
                observables.push(observable);
            }
        }
        let mut result = ResultEnvelope::new(UrlExtractionAnalysis {
            urls: ordered.clone(),
            urls_grouped_by_domain: groups.into_iter().collect(),
        });
        result.summary = summary(&ordered);
        result.observables = observables;
        Ok(Outcome::Done(result))
    }
}
