//! `file_hash_analyzer`: ace3's `FileHashAnalyzer` (`saq/modules/file_analysis/hash.py`).
//!
//! The file's MD5, SHA-1 and SHA-256, with MD5 and SHA-256 observables that are hashes of it,
//! unless the file is empty, or its path or its mime type matches an ignore pattern.
//!
//! Where ace4 departs:
//!
//! - ace3's patterns are config keys that start `ignore_pattern_` and `ignore_mime_type_`, and
//!   `fnmatch` each on the file's path on its node. Here they are two maps, and each path pattern
//!   is matched on the alert path under a directory, which is what ace3's path ends with: a
//!   pattern that starts with `*`, as all but two of ace3's do, matches as it does there, and one
//!   that doesn't, `email.rfc822.combined` and `phishkit/*`, never matches in either. ace3's
//!   default config also has `ignore_pattenr_eml` and `ignore_pattenr_eml_extra`, which its code
//!   never reads; they aren't here.
//! - ace3 also links each hash to the file for its alert page; ace4's relationship is the link.

use std::collections::BTreeMap;
use std::fs;

use ace_pycompat::fnmatch::fnmatch;
use ace_results::types::file_hash::FileHashAnalysis;
use ace_results::types::file_type::FileTypeAnalysis;
use ace_results::{
    AnalysisType, NewObservable, ObservableKind, ObservableRef, Relationship, RelationshipKind,
    ResultEnvelope,
};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};
use md5::Md5;
use schemars::JsonSchema;
use serde::Deserialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<FileHashAnalyzer>();

/// ace3's `analysis_module_file_hash_analyzer` settings.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct FileHashSettings {
    /// Globs on the file's path, by name: ace3's `ignore_pattern_<name>` keys.
    pub ignore_patterns: BTreeMap<String, String>,
    /// Globs on the file's mime type, by name: ace3's `ignore_mime_type_<name>` keys.
    pub ignore_mime_types: BTreeMap<String, String>,
}

impl Default for FileHashSettings {
    fn default() -> Self {
        let map = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        };
        FileHashSettings {
            ignore_patterns: map(&[
                ("pcap", "*.pcap"),
                ("stderr", "*.stderr"),
                ("stdout", "*.stdout"),
                ("pdfparser", "*.pdfparser"),
                ("stream", "*.stream"),
                ("noxml", "*.noxml"),
                ("ole", "*/ole.stdout.analysis"),
                ("officeparser", "*.officeparser/*"),
                ("email_headers", "*email.rfc822.headers"),
                ("email_plain_text", "*email.rfc822.unknown_text_plain_*"),
                ("email_combined", "email.rfc822.combined"),
                ("email_html", "*.unknown_text_html_*"),
                ("json", "*.json"),
                ("extra_001", "*.crl"),
                ("extra_002", "*/xl/drawings/*"),
                ("extra_003", "*/xl/media/*"),
                ("extra_004", "*/xl/printerSettings/*"),
                ("extra_005", "*/xl/theme/*"),
                ("extra_006", "*.rels"),
                ("extra_007", "*/xl/vbaProject.bin"),
                ("extra_008", "*.extracted/xl/*.bin"),
                ("pdf_txt", "*.pdf.txt"),
                ("olevba", "*.olevba/*.bas"),
                ("pcode", "*.pcode.bas"),
                ("phishkit", "phishkit/*"),
                ("gs", "*.pdf.gs.pdf"),
                ("ocr", "*.ocr"),
                ("js_deobfuscated", "*/deobfuscated-*"),
            ]),
            ignore_mime_types: map(&[
                ("xml", "application/xml"),
                ("text_xml", "text/xml"),
                ("images", "image/*"),
                ("email", "message/rfc822"),
            ]),
        }
    }
}

pub struct FileHashAnalyzer;

impl Module for FileHashAnalyzer {
    const NAME: &'static str = FileHashAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const DEPENDS_ON: &'static [&'static str] = &[FileTypeAnalysis::MODULE];
    type Output = FileHashAnalysis;
    type Settings = FileHashSettings;

    fn init(_: &FileHashSettings) -> Result<Self, ModuleError> {
        Ok(FileHashAnalyzer)
    }
}

/// The path ace3 matches, its file's path on its node: a directory, then the alert path.
fn node_path(alert_path: &str) -> String {
    format!("/opt/ace/data/root/{alert_path}")
}

/// The ignore pattern the file matches, if one does.
pub fn ignored_by(settings: &FileHashSettings, alert_path: &str, mime: &str) -> Option<String> {
    let path = node_path(alert_path);
    if let Some(pattern) = settings
        .ignore_patterns
        .values()
        .find(|p| fnmatch(&path, p))
    {
        return Some(pattern.clone());
    }
    settings
        .ignore_mime_types
        .values()
        .find(|p| fnmatch(mime, p))
        .cloned()
}

impl Parser for FileHashAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<FileHashSettings>,
    ) -> Result<Outcome<FileHashAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        if file.size == 0 {
            return Ok(Outcome::Skipped("an empty file".to_owned()));
        }
        let Some(file_type) = ctx.dependency_result::<FileTypeAnalysis>()? else {
            return Ok(Outcome::Skipped("no file type analysis".to_owned()));
        };
        if let Some(pattern) = ignored_by(ctx.settings(), file.path.as_str(), &file_type.mime) {
            return Ok(Outcome::Skipped(format!("ignored by {pattern}")));
        }
        let data = fs::read(&file.local_path)?;
        let md5 = hex(&Md5::digest(&data));
        let sha1 = hex(&Sha1::digest(&data));
        let sha256 = hex(&Sha256::digest(&data));
        let hash_of = |kind, value: &str| {
            let mut observable = NewObservable::new(kind, value);
            observable.relationships.push(Relationship::new(
                RelationshipKind::IsHashOf,
                ObservableRef::new(ObservableKind::File, file.sha256.to_hex()),
            ));
            observable
        };
        let mut result = ResultEnvelope::new(FileHashAnalysis {
            md5: Some(md5.clone()),
            sha1: Some(sha1),
            sha256: Some(sha256.clone()),
        });
        result.observables = vec![
            hash_of(ObservableKind::Md5, &md5),
            hash_of(ObservableKind::Sha256, &sha256),
        ];
        Ok(Outcome::Done(result))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ace3_s_patterns_match_as_they_do_on_its_node() {
        let settings = FileHashSettings::default();
        let ignored = |path: &str, mime: &str| ignored_by(&settings, path, mime);
        assert!(ignored("email.rfc822.headers", "text/plain").is_some());
        assert!(ignored("email.rfc822.combined", "text/plain").is_none());
        assert!(ignored("phishkit/a.html", "text/html").is_none());
        assert!(ignored("a.xlsx.extracted/xl/media/i.png", "x/y").is_some());
        assert!(ignored("a.png", "image/png").is_some());
        assert!(ignored("a.eml", "text/plain").is_none());
        assert!(ignored("invoice.pdf", "application/pdf").is_none());
    }
}
