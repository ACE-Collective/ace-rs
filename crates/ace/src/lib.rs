//! The open-source pools and their modules, which the open-source binaries are built from and a
//! site's `App` can start from (PLAN.md 2.31).

use ace_app::{App, LookupPool, ParserPool, ScannerPool};

/// The parser pool: the email, olevba, rtfole, YARA, URL and IOC extraction, file type, file hash,
/// binary file, shortcut, certificate, dhash and ssdeep modules, the modules that read an
/// observable's value (command lines, file paths and locations, networks, URLs, IDNA, email
/// addresses' domains and protected URLs), the HTML modules (data URLs, HTTP archives, scripts in HTML
/// and MHTML), the Office container modules (OneNote, compound files, Office XML, hidden MIME and
/// ActiveMime), the RTF and script modules (encoded scripts, hex in VBScript, an RTF's objects and
/// its copy without whitespace), the encrypted attachment modules (zip, RAR and PDF, with the carrying
/// email's candidate passwords), the modules that walk an email's tree (its lure URL, a mailbox alert's
/// root, and a macro or a URL from a new sender), the packet capture modules that read
/// pcap_analyzer's index (DNS, TLS, HTTP and files), the TLS key log module, the site tagger, and the two that send a
/// file or a URL through a scanner image (JavaScript deobfuscation and phishkit, 7.7), with the YARA module on the core's current ruleset (2.26), and the commands analysts
/// start from the GUI (5.12).
pub fn parser_pool() -> ParserPool {
    ParserPool::new("parsers")
        .module::<ace_mod_email::EmailAnalyzer>()
        .module::<ace_mod_oletools::Olevba>()
        .module::<ace_mod_oletools::RtfOle>()
        .module::<ace_mod_msoffice::MsofficeEncryption>()
        .module::<ace_mod_xlm::XlmDeobfuscator>()
        .module::<ace_mod_xlm::PCode>()
        .module::<ace_mod_yara::YaraScanner>()
        .module::<ace_mod_urls::UrlExtraction>()
        .module::<ace_mod_urls::IocExtraction>()
        .module::<ace_mod_files::FileType>()
        .module::<ace_mod_files::FileHashAnalyzer>()
        .module::<ace_mod_files::BinaryFileAnalyzer>()
        .module::<ace_mod_files::LnkParseAnalyzer>()
        .module::<ace_mod_files::X509Analyzer>()
        .module::<ace_mod_files::DHashImageAnalyzer>()
        .module::<ace_mod_files::SsdeepAnalyzer>()
        .module::<ace_mod_values::CommandLineAnalyzer>()
        .module::<ace_mod_values::FilePathAnalyzer>()
        .module::<ace_mod_values::FileLocationAnalyzer>()
        .module::<ace_mod_values::NetworkIdentifier>()
        .module::<ace_mod_values::ParseUrlAnalyzer>()
        .module::<ace_mod_values::IdnaAnalyzer>()
        .module::<ace_mod_values::EmailAddressFqdnAnalyzer>()
        .module::<ace_mod_values::ProtectedUrlAnalyzer>()
        .module::<ace_mod_html::HtmlDataUrlAnalyzer>()
        .module::<ace_mod_html::HarExtractor>()
        .module::<ace_mod_html::HtmlJavaScriptExtractor>()
        .module::<ace_mod_html::MhtmlAnalyzer>()
        .module::<ace_mod_office::OneNoteAnalyzer>()
        .module::<ace_mod_office::OfficeParserAnalyzer>()
        .module::<ace_mod_office::OfficeXmlRelAnalyzer>()
        .module::<ace_mod_office::XmlBinaryAnalyzer>()
        .module::<ace_mod_office::XmlPlainTextAnalyzer>()
        .module::<ace_mod_office::ExtractedOleAnalyzer>()
        .module::<ace_mod_office::HiddenMimeAnalyzer>()
        .module::<ace_mod_office::ActiveMimeAnalyzer>()
        .module::<ace_mod_scripts::MicrosoftScriptEncodingAnalyzer>()
        .module::<ace_mod_scripts::ExtractedRtfAnalyzer>()
        .module::<ace_mod_scripts::VbScriptAnalyzer>()
        .module::<ace_mod_scripts::NoWhiteSpaceAnalyzer>()
        .module::<ace_mod_encrypted::ZipEncryptionAnalyzer>()
        .module::<ace_mod_encrypted::RarEncryptionAnalyzer>()
        .module::<ace_mod_encrypted::PdfEncryptionAnalyzer>()
        .module::<ace_mod_emailtree::LureUrlAnalyzer>()
        .module::<ace_mod_emailtree::MailboxEmailAnalyzer>()
        .module::<ace_mod_brocess::EmailConversationAttachmentAnalyzer>()
        .module::<ace_mod_brocess::EmailConversationLinkAnalyzer>()
        .module::<ace_mod_pcap::PcapDns>()
        .module::<ace_mod_pcap::PcapTls>()
        .module::<ace_mod_pcap::PcapHttp>()
        .module::<ace_mod_pcap::PcapFiles>()
        .module::<ace_mod_pcap::TlsKeylogAnalyzer>()
        .module::<ace_mod_tag::SiteTagger>()
        .module::<ace_mod_scanners::JavaScriptDeobfuscationAnalyzer>()
        .module::<ace_mod_scanners::PhishkitAnalyzer>()
        .yara_rulesets::<ace_mod_yara::YaraScanner>(
            ace_mod_yara::check_ruleset,
            ace_mod_yara::prepare_ruleset,
        )
        .commands()
}

/// The sandbox pool (PLAN.md 7.3, 7.5 batches 10 to 12): a parser pool whose image carries the
/// programs its modules run in the sandbox runner (`ace_sdk::tools::SANDBOX_TOOLS`): the archive
/// module, for ACE archives' unace; the PDF module, for Ghostscript's rewrite; pdftotext, the PDF
/// link text module, which runs pdftotext too, exif, qrcode and ocr; the unpackers and decompilers, java_class_decompiler, upx, autoit, de4dot
/// and ilspy; the macOS image modules, dmg_analyzer and cve_2021_30657_analyzer; and the two
/// packet capture modules that run tshark, pcap_analyzer and pcap_tls_decryption.
pub fn sandbox_pool() -> ParserPool {
    ParserPool::new("sandbox")
        .tools(ace_sdk::tools::SANDBOX_TOOLS)
        .module::<ace_mod_archive::ArchiveAnalyzer>()
        .module::<ace_mod_pdf::PdfAnalyzer>()
        .module::<ace_mod_sandbox::PdfTextAnalyzer>()
        .module::<ace_mod_pdf::PdfLinkTextAnalyzer>()
        .module::<ace_mod_sandbox::ExifAnalyzer>()
        .module::<ace_mod_sandbox::QrCodeAnalyzer>()
        .module::<ace_mod_sandbox::OcrAnalyzer>()
        .module::<ace_mod_sandbox::JavaClassDecompiler>()
        .module::<ace_mod_sandbox::UpxAnalyzer>()
        .module::<ace_mod_sandbox::AutoItAnalyzer>()
        .module::<ace_mod_sandbox::De4dotAnalyzer>()
        .module::<ace_mod_sandbox::IlspyAnalyzer>()
        .module::<ace_mod_sandbox::DmgAnalyzer>()
        .module::<ace_mod_sandbox::Cve202130657Analyzer>()
        .module::<ace_mod_pcap::PcapAnalyzer>()
        .module::<ace_mod_pcap::PcapTlsDecryptor>()
}

/// The scanner pool (PLAN.md 7.7): ace3's js-deobfuscator and phishkit images, which the parser pool's
/// javascript_deobfuscation and phishkit_analyzer modules send their scans to.
pub fn scanner_pool() -> ScannerPool {
    ScannerPool::new("scanners")
        .scanner(ace_sdk::scanners::JS_DEOBFUSCATOR)
        .scanner(ace_sdk::scanners::PHISHKIT)
}

/// The network pool: the RDAP, DNS, snort signature, conversation frequency, email logger, email
/// thread, newly registered domains, user (LDAP), Splunk and Splunk clicker detection modules, the
/// one that follows 1drv.ms links for the protected URL module, the four on the email archive
/// (its archiver, the archived email opener, the URL pivot and the Message-ID analyzer), and the
/// two that read what analysts flagged and tagged (observable detection and user defined tagging), SVS's
/// sample capture (7.10), and
/// ace3's test remediator (7.9), the one remediator ace3's open-source tree ships.
pub fn lookup_pool() -> LookupPool {
    LookupPool::new("lookups")
        .module::<ace_mod_rdap::RdapAnalyzer>()
        .module::<ace_mod_dns::FqdnAnalyzer>()
        .module::<ace_mod_snort::SnortSignatureAnalyzer>()
        .module::<ace_mod_brocess::EmailConversationFrequencyAnalyzer>()
        .module::<ace_mod_brocess::EmailLogger>()
        .module::<ace_mod_brocess::EmailThreadAnalyzer>()
        .module::<ace_mod_nrd::NrdAnalyzer>()
        .module::<ace_mod_user::UserAnalyzer>()
        .module::<ace_mod_splunk::SplunkAnalyzer>()
        .module::<ace_mod_splunk::ClickerDetection>()
        .module::<ace_mod_values::OneDriveUrlAnalyzer>()
        .module::<ace_mod_emailarchive::EmailArchiver>()
        .module::<ace_mod_emailarchive::MessageIdAnalyzer>()
        .module::<ace_mod_tag::ObservableDetection>()
        .module::<ace_mod_tag::UserDefinedTagging>()
        .module::<ace_mod_svs::YaraSampleCapture>()
        // ace3's one open-source remediator, which it ships enabled (PLAN.md 7.9)
        .action(&ace_sdk::actions::TEST_REMEDIATOR, |_| {
            Ok(ace_app::ActionHandler::Remediator(std::sync::Arc::new(
                ace_sdk::actions::TestRemediator,
            )))
        })
}

/// The open-source binaries' list: the four pools, no observable types beyond ace3's, ace3's
/// one open-source hunt type, Splunk (PLAN.md 6.2), and no hunt script command types, which a
/// site's binary adds for its own scripts (decision 16). `ace hunter` checks the Splunk instance a
/// hunt names against the overlay's Splunk connections (6.4, decision 41), and so does `ace
/// signatures check --overlay`; elsewhere a hunt's `splunk_config` isn't checked.
pub fn app() -> App {
    App::new()
        .parser_pool(parser_pool())
        .parser_pool(sandbox_pool())
        .lookup_pool(lookup_pool())
        .scanner_pool(scanner_pool())
        // ace3's protected_url_analyzer is in its common group, and this does its network half
        .module_in_group("common", "protected_url_one_drive")
        .hunt_type(ace_hunt::types::Splunk::default())
}

#[cfg(test)]
mod tests {
    /// Every open-source module's results have their view (PLAN.md 5.9).
    #[test]
    fn every_module_has_an_analysis_view() {
        assert_eq!(super::app().modules_without_a_view(), []);
    }

    /// Every open-source module's declaration of what it takes reads only what its lease carries
    /// (PLAN.md decision 23).
    #[test]
    fn every_module_s_declaration_reads_what_its_lease_carries() {
        assert_eq!(
            super::app().modules_with_unusable_declarations(),
            Vec::<String>::new()
        );
    }

    /// Every open-source module that opts into the analysis cache reads only what its key holds, and
    /// its pool can read the version of every tool it keys on (PLAN.md decision 26). The modules that
    /// opt in are ace3's at `fe6da632`.
    #[test]
    fn every_cacheable_module_reads_only_what_its_key_holds() {
        let app = super::app();
        assert_eq!(app.modules_that_cannot_be_cached(), Vec::<String>::new());
        let cached = app.cacheable_modules();
        assert_eq!(
            cached,
            [
                "site_tagger",
                "phishkit_analyzer",
                "pdf_link_text",
                "qrcode",
                "ocr",
                "rdap_analyzer",
                "nrd_analyzer"
            ]
        );
    }

    /// The open-source binary has no hunt script command types: a site's binary registers its own
    /// (PLAN.md decision 16, `App::hunt_script`).
    #[test]
    fn the_open_source_binary_has_no_hunt_scripts() {
        assert!(super::app().hunt_script_names().is_empty());
    }

    /// The list's groups are ace3's and its modules registered, so `ace` starts with no overlay
    /// (`App::check_overlay`, which every `ace` command runs on the overlay it reads).
    #[test]
    fn the_list_takes_an_empty_overlay() {
        assert_eq!(
            super::app().check_overlay(&ace_sdk::Overlay::default()),
            Ok(())
        );
    }

    /// ace3's open-source hunt type; a site's binary adds its own, such as LogScale, in its own list.
    #[test]
    fn the_open_source_hunt_type_is_splunk() {
        let app = super::app();
        let names: Vec<&str> = app.hunt_types().iter().map(|k| k.name()).collect();
        assert_eq!(names, ["splunk"]);
    }
}
