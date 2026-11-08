//! The open-source pools and their modules, which the open-source binaries are built from and a
//! site's `App` can start from (PLAN.md 2.31).

use ace_app::{App, LookupPool, ParserPool};

/// The parser pool: the email, archive, PDF, olevba, rtfole and YARA modules, with the YARA module on the core's
/// current ruleset (2.26), and the commands analysts start from the GUI (5.12).
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
        .commands()
}

/// The network pool: the RDAP, DNS, snort signature, conversation frequency, email logger, email
/// thread and Splunk modules.
pub fn lookup_pool() -> LookupPool {
    LookupPool::new("lookups")
        .module::<ace_mod_rdap::RdapAnalyzer>()
        .module::<ace_mod_dns::FqdnAnalyzer>()
        .module::<ace_mod_snort::SnortSignatureAnalyzer>()
        .module::<ace_mod_brocess::EmailConversationFrequencyAnalyzer>()
        .module::<ace_mod_brocess::EmailLogger>()
        .module::<ace_mod_brocess::EmailThreadAnalyzer>()
        .module::<ace_mod_splunk::SplunkAnalyzer>()
}

/// The open-source binaries' list: the two pools, no observable types beyond ace3's, and ace3's
/// one open-source hunt type, Splunk (PLAN.md 6.2). `ace hunter` checks the Splunk instance a hunt
/// names against its configuration's (6.4); elsewhere a hunt's `splunk_config` isn't checked.
pub fn app() -> App {
    App::new()
        .parser_pool(parser_pool())
        .lookup_pool(lookup_pool())
        .hunt_type(ace_hunt::types::Splunk::default())
}

#[cfg(test)]
mod tests {
    /// Every open-source module's results have their view (PLAN.md 5.9).
    #[test]
    fn every_module_has_an_analysis_view() {
        assert_eq!(super::app().modules_without_a_view(), []);
    }

    /// ace3's open-source hunt type; a site's add LogScale and Rapid7 in its own app.
    #[test]
    fn the_open_source_hunt_type_is_splunk() {
        let app = super::app();
        let names: Vec<&str> = app.hunt_types().iter().map(|k| k.name()).collect();
        assert_eq!(names, ["splunk"]);
    }
}
