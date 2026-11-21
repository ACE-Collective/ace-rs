//! Analysis modes and module groups, carried over from ace3.
//!
//! A root's analysis mode names the module groups that run on it, plus modules the mode enables
//! or disables one by one. The groups and modes below are ace3's `module_group_*` and
//! `analysis_mode_*` sections of `etc/saq.default.yaml` (lines 2538 to 2847 at the commit the
//! plan read), and the non-detectable modes and default mode are its `service_engine`
//! `non_detectable_modes` and `default_analysis_mode`.
//!
//! The lists name modules ace4 doesn't have yet. Eligibility only considers modules it has a
//! manifest for, so a name with none is skipped, as ace3 skips a module with no config (#916).
//! A module's name is a string so a named instance (PLAN.md 2.23) can join a group.

use std::collections::{BTreeMap, BTreeSet};

/// A module group: a name for a set of modules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleGroup {
    pub name: String,
    pub modules: Vec<String>,
}

/// An analysis mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisMode {
    pub name: String,
    pub module_groups: Vec<String>,
    /// Modules the mode runs besides its groups'.
    pub enabled_modules: Vec<String>,
    /// Modules the mode leaves out even when a group has them.
    pub disabled_modules: Vec<String>,
}

/// Every mode and group, and which modes a detection turns into an alert from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modes {
    groups: BTreeMap<String, ModuleGroup>,
    modes: BTreeMap<String, AnalysisMode>,
    /// Modes in which a detection doesn't make the root an alert.
    non_detectable: BTreeSet<String>,
    default_mode: String,
}

/// The mode a root becomes an alert in.
pub const CORRELATION: &str = "correlation";
/// The mode an alert switches to when an analyst dispositions it.
pub const DISPOSITIONED: &str = "dispositioned";

fn strings(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| (*n).to_owned()).collect()
}

impl Modes {
    pub fn new(
        groups: Vec<ModuleGroup>,
        modes: Vec<AnalysisMode>,
        non_detectable: &[&str],
        default_mode: &str,
    ) -> Modes {
        Modes {
            groups: groups.into_iter().map(|g| (g.name.clone(), g)).collect(),
            modes: modes.into_iter().map(|m| (m.name.clone(), m)).collect(),
            non_detectable: non_detectable.iter().map(|m| (*m).to_owned()).collect(),
            default_mode: default_mode.to_owned(),
        }
    }

    /// ace3's modes and groups.
    pub fn ace3() -> Modes {
        let group = |name: &str, modules: &[&str]| ModuleGroup {
            name: name.to_owned(),
            modules: strings(modules),
        };
        let mode = |name: &str, groups: &[&str], enabled: &[&str]| AnalysisMode {
            name: name.to_owned(),
            module_groups: strings(groups),
            enabled_modules: strings(enabled),
            disabled_modules: Vec::new(),
        };
        Modes::new(
            vec![
                group(
                    "correlation",
                    &[
                        "clicker_detection_splunk",
                        "email_thread_analyzer",
                        "fqdn_analyzer",
                        "idna_analyzer",
                        "lure_url_analyzer",
                        "message_id_analyzer_v2",
                        "network_identifier",
                        "parse_url",
                        "pdf_link_text",
                        "phishkit_analyzer",
                        "rdap_analyzer",
                        "snort_signature_analysis_v1",
                        "user_analyzer",
                    ],
                ),
                group("yara", &["yara_scanner_v3_4"]),
                group(
                    "file",
                    &[
                        "active_mime",
                        "archive",
                        "autoit",
                        "binary_file_analyzer",
                        "cve_2021_30657_analyzer",
                        "de4dot",
                        "dhash",
                        "dmg_analyzer",
                        "exif",
                        "extracted_ole_analyzer",
                        "extracted_rtf_analyzer",
                        "file_hash_analyzer",
                        "file_location_analysis",
                        "file_path_analysis",
                        "file_type",
                        "har_extraction",
                        "hidden_mime",
                        "html_data_url_extraction",
                        "html_js_extraction",
                        "ilspy",
                        "ioc_extraction",
                        "java_class_decompiler",
                        "javascript_deobfuscation",
                        "lnk_parser",
                        "mhtml",
                        "microsoft_script_encoding_analysis",
                        "msoffice_encryption_analyzer",
                        "nowhitespace_analyzer",
                        "ocr",
                        "office_xml_rel",
                        "officeparser3",
                        "olevba_v1_2",
                        "onenote_extraction",
                        "pcap_analyzer",
                        "pcap_dns",
                        "pcap_files",
                        "pcap_http",
                        "pcap_tls",
                        "pcap_tls_decryption",
                        "pcodedmp",
                        "pdf_analyzer",
                        "pdf_encryption_analyzer",
                        "pdftotext",
                        "phishkit_analyzer",
                        "qrcode",
                        "rar_encryption_analyzer",
                        "rtfole",
                        "site_tagger",
                        "ssdeep",
                        "tls_keylog",
                        "upx",
                        "url_extraction",
                        "vbscript_analyzer",
                        "x509_analyzer",
                        "xlmdeobfuscator",
                        "xml_binary_analyzer",
                        "xml_plain_text_analyzer",
                        "yara_scanner_v3_4",
                        "zip_encryption_analyzer",
                    ],
                ),
                group(
                    "email",
                    &[
                        "email_analyzer",
                        "email_conversation_attachment_analyzer",
                        "email_conversation_frequency_analyzer",
                        "email_conversation_link_analyzer",
                        "mailbox_email_analyzer",
                    ],
                ),
                group(
                    "common",
                    &[
                        "command_line_analyzer",
                        "configuration_defined_tagging",
                        "email_address_fqdn_analyzer",
                        "nrd_analyzer",
                        "observable_detection",
                        "observable_modifier",
                        "protected_url_analyzer",
                        "site_tagger",
                        "user_defined_tagging",
                    ],
                ),
            ],
            vec![
                mode("yara", &["yara"], &[]),
                mode(
                    "email",
                    &["common", "file", "email"],
                    &["email_archiver", "email_logger"],
                ),
                mode("binary", &["common", "file"], &[]),
                mode("file", &["common", "file"], &[]),
                mode(
                    CORRELATION,
                    &["common", "file", "email", "correlation"],
                    &["svs_alert_tagger"],
                ),
                mode("analysis", &["common", "file", "email", "correlation"], &[]),
                mode("cli", &["common", "file", "email", "correlation"], &[]),
                mode(
                    DISPOSITIONED,
                    &[],
                    &["alert_added_to_event", "svs_yara_sample_capture"],
                ),
                mode("event", &[], &[]),
                mode("suricata_ids", &[], &["snort_signature_analysis_v1"]),
            ],
            &[CORRELATION, DISPOSITIONED, "event"],
            "analysis",
        )
    }

    /// Adds `module` to the group `group`, creating the group if there's none, as a site's
    /// configuration appends to ace3's `module_group_*` lists.
    pub fn with_module_in_group(mut self, group: &str, module: &str) -> Modes {
        let entry = self
            .groups
            .entry(group.to_owned())
            .or_insert_with(|| ModuleGroup {
                name: group.to_owned(),
                modules: Vec::new(),
            });
        if !entry.modules.iter().any(|m| m == module) {
            entry.modules.push(module.to_owned());
        }
        self
    }

    /// Adds `module` to the enabled modules of the mode `mode`, as a site's configuration appends to
    /// ace3's `analysis_mode_*` `enabled_modules`, so it runs in that mode whatever its groups. A
    /// module both here and in one of the mode's groups runs once, as ace3's mode is the union of
    /// the two. Leaves the modes as they are when there's no mode `mode`; `ace_app::App` refuses
    /// that before it builds the modes.
    pub fn with_module_in_mode(mut self, mode: &str, module: &str) -> Modes {
        if let Some(entry) = self.modes.get_mut(mode)
            && !entry.enabled_modules.iter().any(|m| m == module)
        {
            entry.enabled_modules.push(module.to_owned());
        }
        self
    }

    /// The names of every module group.
    pub fn group_names(&self) -> impl Iterator<Item = &str> {
        self.groups.keys().map(String::as_str)
    }

    /// The names of every mode.
    pub fn mode_names(&self) -> impl Iterator<Item = &str> {
        self.modes.keys().map(String::as_str)
    }

    /// Adds a mode, or replaces the one with its name.
    pub fn with_mode(mut self, mode: AnalysisMode) -> Modes {
        self.modes.insert(mode.name.clone(), mode);
        self
    }

    pub fn mode(&self, name: &str) -> Option<&AnalysisMode> {
        self.modes.get(name)
    }

    pub fn group(&self, name: &str) -> Option<&ModuleGroup> {
        self.groups.get(name)
    }

    /// The mode a root gets when its submission names none.
    pub fn default_mode(&self) -> &str {
        &self.default_mode
    }

    /// The modules that run in `mode`: its groups' modules and its enabled modules, without
    /// its disabled ones. An unknown mode runs nothing.
    pub fn modules_in(&self, mode: &str) -> BTreeSet<&str> {
        let Some(mode) = self.modes.get(mode) else {
            return BTreeSet::new();
        };
        let mut modules: BTreeSet<&str> = mode
            .module_groups
            .iter()
            .filter_map(|g| self.groups.get(g))
            .flat_map(|g| g.modules.iter().map(String::as_str))
            .chain(mode.enabled_modules.iter().map(String::as_str))
            .collect();
        for disabled in &mode.disabled_modules {
            modules.remove(disabled.as_str());
        }
        modules
    }

    /// True when a detection in `mode` turns the root into an alert.
    pub fn is_detectable(&self, mode: &str) -> bool {
        !self.non_detectable.contains(mode)
    }

    /// The modules the modes and groups name that aren't in `known`, for a warning at start.
    pub fn unknown_modules<'a>(&'a self, known: &BTreeSet<&str>) -> BTreeSet<&'a str> {
        self.groups
            .values()
            .flat_map(|g| g.modules.iter())
            .chain(
                self.modes
                    .values()
                    .flat_map(|m| m.enabled_modules.iter().chain(&m.disabled_modules)),
            )
            .map(String::as_str)
            .filter(|m| !known.contains(m))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_name_ace3s_groups_and_modules() {
        let modes = Modes::ace3();
        let email = modes.modules_in("email");
        assert!(email.contains("email_analyzer"));
        assert!(email.contains("archive"));
        assert!(email.contains("yara_scanner_v3_4"));
        assert!(email.contains("email_archiver"));
        assert!(
            !email.contains("rdap_analyzer"),
            "correlation isn't an email group"
        );
        assert!(modes.modules_in(CORRELATION).contains("rdap_analyzer"));
        assert_eq!(
            modes.modules_in(DISPOSITIONED),
            BTreeSet::from(["alert_added_to_event", "svs_yara_sample_capture"])
        );
        assert_eq!(
            modes.modules_in("yara"),
            BTreeSet::from(["yara_scanner_v3_4"])
        );
        assert!(modes.modules_in("event").is_empty());
        assert!(modes.modules_in("no_such_mode").is_empty());
        assert!(modes.is_detectable("email"));
        assert!(modes.is_detectable("analysis"));
        assert!(!modes.is_detectable(CORRELATION));
        assert!(!modes.is_detectable("event"));
        assert_eq!(modes.default_mode(), "analysis");
    }

    #[test]
    fn a_sites_module_joins_a_group() {
        let modes = Modes::ace3()
            .with_module_in_group("correlation", "site_lookup")
            .with_module_in_group("correlation", "site_lookup")
            .with_module_in_group("site", "site_parser");
        assert!(modes.modules_in("analysis").contains("site_lookup"));
        assert!(modes.modules_in("analysis").contains("rdap_analyzer"));
        assert!(!modes.modules_in("email").contains("site_lookup"));
        let correlation = modes.group("correlation").expect("the group");
        assert_eq!(
            correlation
                .modules
                .iter()
                .filter(|m| *m == "site_lookup")
                .count(),
            1
        );
        // a new group runs in no mode until one names it
        assert!(!modes.modules_in("analysis").contains("site_parser"));
    }

    /// ace3's `analysis_mode_<mode>: enabled_modules:` from a site: the module runs in that mode
    /// and no other, and one both there and in a group runs where either puts it, once.
    #[test]
    fn a_sites_module_joins_one_mode() {
        let modes = Modes::ace3()
            .with_module_in_mode(CORRELATION, "site_lookup")
            .with_module_in_mode(CORRELATION, "site_lookup")
            .with_module_in_mode("no_such_mode", "site_lookup")
            .with_module_in_group("correlation", "site_both")
            .with_module_in_mode(CORRELATION, "site_both");
        let running: Vec<&str> = modes
            .mode_names()
            .filter(|m| modes.modules_in(m).contains("site_lookup"))
            .collect();
        assert_eq!(running, [CORRELATION]);
        let enabled = &modes.mode(CORRELATION).expect("the mode").enabled_modules;
        assert_eq!(enabled, &["svs_alert_tagger", "site_lookup", "site_both"]);
        // the union: every mode that runs the correlation group, and correlation once
        let both: Vec<&str> = modes
            .mode_names()
            .filter(|m| modes.modules_in(m).contains("site_both"))
            .collect();
        assert_eq!(both, ["analysis", "cli", CORRELATION]);
        assert!(modes.mode("no_such_mode").is_none());
    }

    #[test]
    fn a_disabled_module_leaves_its_mode() {
        let modes = Modes::new(
            vec![ModuleGroup {
                name: "g".to_owned(),
                modules: strings(&["a", "b"]),
            }],
            vec![AnalysisMode {
                name: "m".to_owned(),
                module_groups: strings(&["g"]),
                enabled_modules: strings(&["c"]),
                disabled_modules: strings(&["b"]),
            }],
            &[],
            "m",
        );
        assert_eq!(modes.modules_in("m"), BTreeSet::from(["a", "c"]));
        assert_eq!(
            modes.unknown_modules(&BTreeSet::from(["a"])),
            BTreeSet::from(["b", "c"])
        );
    }
}
