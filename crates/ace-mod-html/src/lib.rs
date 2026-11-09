//! ace3's HTML modules (PLAN.md 7.5 batch 4): `html_data_url_extraction`, `har_extraction`,
//! `html_js_extraction` and `mhtml`. They write the data URLs, pages, scripts and parts they find
//! in HTML, HTTP archive and MHTML files as files, with ace3's names and `yara_meta` types, and the
//! DOM snapshots 7.7's JavaScript deobfuscator reads.
//!
//! HTML is parsed as BeautifulSoup parses it over lxml (`ace_lxml::soup`), MIME by
//! `ace-mod-oletools`' port of Python's feed parser, and JSON, base64 and URLs by `ace-pycompat`.

pub mod data_url;
pub mod dom;
pub mod har;
pub mod js;
pub mod mhtml;
mod py;

use ace_results::YaraMeta;
use ace_sdk::{InputFile, Observable};

pub use data_url::HtmlDataUrlAnalyzer;
pub use har::HarExtractor;
pub use js::HtmlJavaScriptExtractor;
pub use mhtml::MhtmlAnalyzer;

/// ace3's root takes at most this many file observables and this many URLs
/// (`maximum_observable_count`), which ace4's core doesn't, so a module stops writing there.
pub const MAX_FILES: usize = 500;
pub const MAX_URLS: usize = 500;

const DIRECTIVE_CRAWL: &str = "crawl";
const DIRECTIVE_CRAWL_EXTRACTED_URLS: &str = "crawl_extracted_urls";
const DIRECTIVE_PREVIEW: &str = "preview";
/// ace3's `fixed_directives`, which `copy_directives_to` leaves behind.
const FIXED_DIRECTIVES: [&str; 1] = ["archive"];

/// `copy_directives_to`: the observable's directives but the fixed ones, and its `yara_meta`
/// types, which ace3 keeps among its directives.
fn copied_directives(observable: &Observable, file: &InputFile) -> (Vec<String>, Vec<YaraMeta>) {
    let directives = observable
        .directives
        .iter()
        .filter(|d| !FIXED_DIRECTIVES.contains(&d.as_str()))
        .cloned()
        .collect();
    (directives, file.yara_meta.clone())
}

/// `saq.util.strings.format_item_list_for_summary`, with its 20 items.
fn item_list(items: &[String]) -> String {
    let mut result = items[..items.len().min(20)].join(", ");
    if items.len() > 20 {
        result.push_str(&format!(" + {} more", items.len() - 20));
    }
    result
}
