//! The open-source pools and their modules, which the open-source binaries are built from and a
//! site's `App` can start from (PLAN.md 2.31).

use ace_app::{App, LookupPool, ParserPool};

/// The parser pool: the email, archive, PDF, olevba, rtfole and YARA modules, with the YARA module on the core's
/// current ruleset (2.26).
pub fn parser_pool() -> ParserPool {
    ParserPool::new("parsers")
        .module::<ace_mod_email::EmailAnalyzer>()
        .module::<ace_mod_archive::ArchiveAnalyzer>()
        .module::<ace_mod_pdf::PdfAnalyzer>()
        .module::<ace_mod_oletools::Olevba>()
        .module::<ace_mod_oletools::RtfOle>()
        .module::<ace_mod_msoffice::MsofficeEncryption>()
        .module::<ace_mod_xlm::XlmDeobfuscator>()
        .module::<ace_mod_xlm::PCode>()
        .module::<ace_mod_yara::YaraScanner>()
        .yara_rulesets::<ace_mod_yara::YaraScanner>(ace_mod_yara::check_ruleset)
}

/// The network pool: the RDAP and Splunk modules.
pub fn lookup_pool() -> LookupPool {
    LookupPool::new("lookups")
        .module::<ace_mod_rdap::RdapAnalyzer>()
        .module::<ace_mod_splunk::SplunkAnalyzer>()
}

/// The open-source binaries' list: the two pools, and no observable types beyond ace3's.
pub fn app() -> App {
    App::new()
        .parser_pool(parser_pool())
        .lookup_pool(lookup_pool())
}

#[cfg(test)]
mod tests {
    /// Every open-source module's results have their view (PLAN.md 5.9).
    #[test]
    fn every_module_has_an_analysis_view() {
        assert_eq!(super::app().modules_without_a_view(), []);
    }
}
