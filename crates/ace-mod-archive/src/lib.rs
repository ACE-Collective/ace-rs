//! The archive module, a port of ace3's `ArchiveAnalyzer`
//! (`saq/modules/file_analysis/archive.py:152`) onto the zip, sevenz-rust2, flate2 and unrar
//! crates. ace3 runs `unzip`, `7z` and `unrar` and Python's `zipfile`; here the archive is read in
//! the task's own process.
//!
//! It lists the archive, then extracts its files into `<archive>.extracted/`, the riskiest kinds
//! first, at most `max_file_count` of them (`max_jar_file_count` for a JAR; an Office document is
//! extracted whole). Each file is `extracted_from` the archive. A lone file in an archive is
//! always suspect: it is sandboxed, and an executable, script, shortcut, JNLP file or OneNote
//! document in that position is a detection. A part of an Office document redirects to the
//! document, so whatever a part matches sandboxes the document.
//!
//! Encrypted members are tried with the password `infected`, as ace3 does.

pub mod formats;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;

use ace_results::types::archive::ArchiveAnalysis;
use ace_results::{
    Detection, NewFile, ObservableKind, ObservableRef, Relationship, RelationshipKind,
    ResultEnvelope,
};
use ace_sdk::{InputFile, Manifest, Module, ModuleError, Outcome, Parser, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::formats::{Entry, Format};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<ArchiveAnalyzer>();

/// ace3's built-in signature for a lone dangerous file in an archive.
pub const ARCHIVE_SINGLE_DANGEROUS_FILE: &str = "de4bfc85-d827-4e60-a7e3-211b60ad61c8";

/// The archive module's settings, ace3's `analysis_module_archive` section.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ArchiveSettings {
    /// Mime types, by prefix, that are never extracted.
    pub excluded_mime_types: Vec<String>,
    /// An archive with more files than this has only this many extracted; 0 for no limit.
    pub max_file_count: u64,
    /// The same, for a JAR.
    pub max_jar_file_count: u64,
    /// The password tried on encrypted members.
    pub password: String,
}

impl Default for ArchiveSettings {
    fn default() -> Self {
        // ace3's saq.default.yaml
        ArchiveSettings {
            excluded_mime_types: vec![
                "application/x-shockwave-flash".to_owned(),
                "application/x-mach-binary".to_owned(),
            ],
            max_file_count: 6,
            max_jar_file_count: 30,
            password: "infected".to_owned(),
        }
    }
}

/// The archive module.
pub struct ArchiveAnalyzer;

impl Module for ArchiveAnalyzer {
    const NAME: &'static str = "archive";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    /// ace3's config makes it wait for file_type, so a file's tags are there before what's
    /// extracted from it is analyzed, which `xml_plain_text_analyzer` reads (7.5 batch 5).
    const DEPENDS_ON: &'static [&'static str] = &["file_type"];
    type Output = ArchiveAnalysis;
    type Settings = ArchiveSettings;

    fn init(_: &ArchiveSettings) -> Result<Self, ModuleError> {
        Ok(ArchiveAnalyzer)
    }
}

/// `KNOWN_OFFICE_EXTENSIONS` in ace3's `is_file_type.py`.
const OFFICE_EXTENSIONS: &[&str] = &[
    "doc", "docb", "dochtml", "docm", "docx", "docxml", "dot", "dothtml", "dotm", "dotx", "odt",
    "rtf", "wbk", "wiz", "csv", "dqy", "iqy", "odc", "ods", "slk", "xla", "xlam", "xlk", "xll",
    "xlm", "xls", "xlsb", "xlshtml", "xlsm", "xlsx", "xlt", "xlthtml", "xltm", "xltx", "xlw",
    "odp", "pot", "pothtml", "potm", "potx", "ppa", "ppam", "pps", "ppsm", "ppsx", "ppt",
    "ppthtml", "pptm", "pptx", "pptxml", "pwz", "sldm", "sldx", "thmx", "mso", "pub",
];

/// Names inside a zip that show it is an Office document even when nothing else says so.
const OFFICE_MEMBERS: &[&str] = &[
    "ppt/slides/_rels",
    "word/document.xml",
    "xl/embeddings/oleObject",
    "xl/worksheets/sheet",
];

/// `order_archive_file_list`: lower comes first.
fn priority(path: &str) -> u8 {
    const ATTACK: &[&str] = &[
        ".lnk", ".one", ".jnlp", ".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".msi", ".hta", ".chm",
        ".cpl", ".scr",
    ];
    const EXECUTABLE: &[&str] = &[
        ".exe", ".dll", ".com", ".bat", ".cmd", ".jar", ".ps1", ".msi", ".sys", ".drv", ".class",
    ];
    const SCRIPT: &[&str] = &[
        ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".psm1", ".sh", ".py", ".rb", ".pl",
        ".php", ".asp", ".aspx",
    ];
    const OFFICE_PDF: &[&str] = &[
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt", ".ods", ".odp", ".pdf",
        ".mht", ".mhtml", ".xml",
    ];
    let lower = path.to_lowercase();
    let has = |exts: &[&str]| exts.iter().any(|ext| lower.ends_with(ext));
    if has(ATTACK) {
        0
    } else if has(EXECUTABLE) {
        1
    } else if has(SCRIPT) {
        2
    } else if has(OFFICE_PDF) {
        3
    } else {
        4
    }
}

/// The lone-file checks: a file name ending, ace3's tag and the detection's description.
const LONE_FILE_KINDS: &[(&[&str], &str, &str)] = &[
    (
        &[".exe", ".scr", ".cpl", ".jar", ".class"],
        "exe_in_zip",
        "An archive contained a single file that was an executable",
    ),
    (
        &[".vbe", ".vbs", ".jse", ".js", ".bat", ".wsh", ".ps1"],
        "script_in_zip",
        "An archive contained a single file that was a script",
    ),
    (
        &[".lnk"],
        "lnk_in_zip",
        "An archive contained a single file that was a shortcut",
    ),
    (
        &[".jnlp"],
        "jnlp_in_zip",
        "An archive contained a single file that was a Java Web Start application",
    ),
    (
        &[".one"],
        "one_in_zip",
        "An archive contained a single file that was a OneNote document",
    ),
];

/// The member's path inside the extraction directory, the way the tool ace3 runs writes it:
/// directories kept, except by `unrar e`, and `..`, `.` and empty parts dropped, as 7z, unzip
/// and `zipfile` drop them. None for a name with nothing left.
pub fn extracted_name(format: Format, name: &str) -> Option<String> {
    let parts: Vec<&str> = name
        .split(['/', '\\'])
        .filter(|p| !p.is_empty() && *p != "." && *p != "..")
        .collect();
    let parts = if format == Format::Rar {
        parts.last().map(|p| vec![*p]).unwrap_or_default()
    } else {
        parts
    };
    let path = parts.join("/").replace('\0', "_");
    (!path.is_empty()).then_some(path)
}

/// unzip's `-x` patterns for an Excel workbook: `*` matches across `/`.
fn excluded_from_xlsx(name: &str) -> bool {
    name.starts_with("xl/activeX/") || (name.starts_with("xl/ctrlProps/") && name.ends_with(".xml"))
}

/// What ace3's file type checks say about the input: the format to open it with, if any.
fn format_of(file: &InputFile, head: &[u8], entries_hint: &dyn Fn() -> bool) -> Option<Format> {
    let mime = file.mime_type.as_deref().unwrap_or_default();
    if head.starts_with(b"Rar!\x1a\x07")
        || mime == "application/x-rar"
        || mime == "application/vnd.rar"
    {
        return Some(Format::Rar);
    }
    let is_zip = head.starts_with(b"PK\x03\x04")
        || head.starts_with(b"PK\x05\x06")
        || head.starts_with(b"PK\x07\x08")
        || mime == "application/zip"
        || mime == "application/java-archive"
        || mime.starts_with("application/vnd.openxmlformats-officedocument");
    if mime == "application/java-archive" || (is_zip && entries_hint()) {
        return Some(Format::Jar);
    }
    if mime == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" {
        return Some(Format::Xlsx);
    }
    if is_zip {
        return Some(Format::Zip);
    }
    if head.starts_with(b"7z\xbc\xaf\x27\x1c") || mime == "application/x-7z-compressed" {
        return Some(Format::SevenZip);
    }
    if head.starts_with(b"\x1f\x8b") || mime == "application/gzip" {
        return Some(Format::Gzip);
    }
    None
}

fn is_ace(file: &InputFile, head: &[u8]) -> bool {
    head.get(7..14) == Some(b"**ACE**") || file.path.as_str().to_lowercase().ends_with(".ace")
}

/// `is_office_file`: an Office file name or mime type.
fn is_office_file(file: &InputFile) -> bool {
    let name = file.name().to_lowercase();
    let by_name = name
        .rsplit_once('.')
        .is_some_and(|(_, ext)| OFFICE_EXTENSIONS.contains(&ext));
    let mime = file.mime_type.as_deref().unwrap_or_default();
    by_name
        || mime.starts_with("application/vnd.openxmlformats-officedocument")
        || mime.starts_with("application/vnd.oasis.opendocument")
        || mime.starts_with("application/vnd.ms-")
        || mime == "application/msword"
}

const PCAP_MAGIC: &[&[u8]] = &[
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
];

fn is_pcap(head: &[u8]) -> bool {
    PCAP_MAGIC.iter().any(|m| head.starts_with(m))
        || (head.starts_with(b"\x0a\x0d\x0d\x0a")
            && matches!(
                head.get(8..12),
                Some(b"\x4d\x3c\x2b\x1a") | Some(b"\x1a\x2b\x3c\x4d")
            ))
}

impl Parser for ArchiveAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<ArchiveSettings>,
    ) -> Result<Outcome<ArchiveAnalysis>, ModuleError> {
        let settings = ctx.settings();
        let file = ctx.input_file()?;
        // an email's archive members are the email module's business (ace3, 10/19/2021)
        if file.path.as_str().contains("email.rfc822") {
            return Ok(Outcome::Skipped("a file of an email".to_owned()));
        }
        let mut head = Vec::with_capacity(16);
        File::open(&file.local_path)?
            .take(16)
            .read_to_end(&mut head)?;
        if is_pcap(&head) {
            return Ok(Outcome::Skipped("a packet capture".to_owned()));
        }
        let mime = file.mime_type.as_deref().unwrap_or_default().to_lowercase();
        if let Some(excluded) = settings
            .excluded_mime_types
            .iter()
            .find(|m| !m.is_empty() && mime.starts_with(&m.to_lowercase()))
        {
            return Ok(Outcome::Skipped(format!("{excluded} is excluded")));
        }
        // ace3 leaves OLE documents to the Office modules, and extracts MSI installers with 7z,
        // which no crate here reads
        if head.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
            return Ok(Outcome::Skipped("an OLE compound file".to_owned()));
        }
        let has_manifest = || {
            formats::list(Format::Zip, &file.local_path, &settings.password)
                .map(|entries| entries.iter().any(|e| e.name == "META-INF/MANIFEST.MF"))
                .unwrap_or(false)
        };
        let Some(format) = format_of(file, &head, &has_manifest) else {
            if is_ace(file, &head) {
                return Ok(Outcome::Skipped(
                    "an ACE archive, which ace3 opens with unace and ace4 can't".to_owned(),
                ));
            }
            return Ok(Outcome::Skipped("not an archive ace4 opens".to_owned()));
        };
        ctx.check_cancelled()?;

        let entries = match formats::list(format, &file.local_path, &settings.password) {
            Ok(entries) => entries,
            Err(e) => {
                tracing::info!(error = %e, "the archive doesn't list");
                return Ok(Outcome::Skipped(format!("the archive doesn't list: {e}")));
            }
        };
        let count = match format {
            Format::Jar | Format::Xlsx | Format::Rar => entries.len(),
            Format::Zip | Format::SevenZip | Format::Gzip => {
                entries.iter().filter(|e| !e.is_dir).count()
            }
        } as u64;
        if count == 0 {
            return Ok(Outcome::Skipped("the archive lists no files".to_owned()));
        }

        let is_office = is_office_file(file)
            || (matches!(format, Format::Zip | Format::Xlsx)
                && entries.iter().any(|e| {
                    OFFICE_MEMBERS.iter().any(|m| e.name.contains(m))
                        || e.name.contains("word/embeddings/oleObject1.bin")
                        || e.name.contains("word\\embeddings\\oleObject1.bin")
                }));
        let limit = if format == Format::Jar {
            settings.max_jar_file_count
        } else if !is_office {
            settings.max_file_count
        } else {
            0
        };
        let limit = (limit != 0 && count > limit).then_some(limit as usize);
        if let Some(limit) = limit {
            tracing::info!(count, limit, "extracting only some of the archive's files");
        }

        let base = format!("{}.extracted", file.path.as_str().replace('*', "_"));
        // the files the tool would write, a later entry of the same name replacing an earlier
        let mut by_path: BTreeMap<String, &Entry> = BTreeMap::new();
        let mut order: Vec<String> = Vec::new();
        for entry in entries.iter().filter(|e| !e.is_dir) {
            if format == Format::Xlsx && excluded_from_xlsx(&entry.name) {
                continue;
            }
            let Some(name) = extracted_name(format, &entry.name) else {
                continue;
            };
            let path = format!("{base}/{name}");
            if by_path.insert(path.clone(), entry).is_some() {
                order.retain(|p| *p != path);
            }
            order.push(path);
        }
        // the riskiest kinds first; within a kind, archive order
        order.sort_by_key(|path| priority(path));
        if let Some(limit) = limit {
            order.truncate(limit);
        }
        let wanted: Vec<usize> = order.iter().map(|p| by_path[p].index).collect();

        let mut written: BTreeMap<usize, NewFile> = BTreeMap::new();
        let mut failure: Option<ModuleError> = None;
        formats::extract(
            format,
            &file.local_path,
            &settings.password,
            &wanted,
            &mut |index, reader| {
                if ctx.is_cancelled() {
                    return Err(std::io::Error::other("cancelled"));
                }
                let Some(path) = order.iter().find(|p| by_path[*p].index == index) else {
                    return Ok(());
                };
                let mut reader = NotesReadError {
                    inner: reader,
                    failed: false,
                };
                match ctx.write_file_from(path, &mut reader, &[]) {
                    Ok(new_file) => {
                        written.insert(index, new_file);
                        Ok(())
                    }
                    // the member, such as an encrypted one with the wrong password: only this
                    // file is lost
                    Err(e) if reader.failed => Err(std::io::Error::other(e.to_string())),
                    // this node's disk or the file limit, which fails the task
                    Err(e) => {
                        let message = e.to_string();
                        failure.get_or_insert(ModuleError::from(e));
                        Err(std::io::Error::other(message))
                    }
                }
            },
            &mut |index, error| {
                tracing::warn!(index, %error, "an archive member didn't extract");
            },
        )
        .map_err(ModuleError::other)?;
        ctx.check_cancelled()?;
        if let Some(failure) = failure {
            return Err(failure);
        }

        let archive_ref = ObservableRef::new(ObservableKind::File, file.sha256.to_hex());
        let mut analysis = ArchiveAnalysis {
            file_count: count,
            extracted_files: Vec::new(),
        };
        let mut result = ResultEnvelope::new(ArchiveAnalysis::default());
        let mut names_so_far: Vec<String> = Vec::new();
        for path in &order {
            let index = by_path[path].index;
            let Some(mut new_file) = written.remove(&index) else {
                continue;
            };
            analysis
                .extracted_files
                .push(path[base.len() + 1..].to_owned());
            new_file.relationships.push(Relationship::new(
                RelationshipKind::ExtractedFrom,
                archive_ref.clone(),
            ));
            if is_office {
                new_file.redirection = Some(archive_ref.clone());
            }
            let name = new_file.name().to_owned();
            let ext = name.rsplit_once('.').map(|(_, ext)| ext.to_lowercase());
            if matches!(ext.as_deref(), Some("xps" | "rels" | "xml")) {
                new_file.add_directive("extract_urls");
            }
            names_so_far.push(name.to_lowercase());
            if count == 1 {
                add_tag(&mut result.tags, "single_file_zip");
                new_file.add_directive("sandbox");
                // ace3 checks every file the analysis holds so far, for the file just added
                for seen in &names_so_far {
                    for (endings, tag, description) in LONE_FILE_KINDS {
                        if endings.iter().any(|e| seen.ends_with(e)) {
                            add_tag(&mut result.tags, tag);
                            new_file.detections.push(
                                Detection::new(*description)
                                    .with_signature(ARCHIVE_SINGLE_DANGEROUS_FILE),
                            );
                        }
                    }
                }
            }
            result.files.push(new_file);
        }
        result.summary = summary(&analysis);
        result.details = analysis;
        Ok(Outcome::Done(result))
    }
}

/// Says whether a read failed, because a failed write of a file doesn't say which side it was.
struct NotesReadError<'a> {
    inner: &'a mut dyn Read,
    failed: bool,
}

impl Read for NotesReadError<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let result = self.inner.read(buf);
        self.failed |= result.is_err();
        result
    }
}

fn add_tag(tags: &mut Vec<String>, tag: &str) {
    if !tags.iter().any(|t| t == tag) {
        tags.push(tag.to_owned());
    }
}

/// `ArchiveAnalysis.generate_summary`.
fn summary(analysis: &ArchiveAnalysis) -> Option<String> {
    if analysis.file_count == 0 {
        return None;
    }
    let mut summary = format!(
        "Archive Analysis: extracted {} of {} files",
        analysis.extracted_files.len(),
        analysis.file_count
    );
    if !analysis.extracted_files.is_empty() {
        let shown: Vec<&str> = analysis
            .extracted_files
            .iter()
            .take(20)
            .map(String::as_str)
            .collect();
        summary.push_str(&format!(": ({}", shown.join(", ")));
        if analysis.extracted_files.len() > 20 {
            summary.push_str(&format!(" + {} more", analysis.extracted_files.len() - 20));
        }
        summary.push(')');
    }
    Some(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_stay_inside_the_extraction_directory() {
        assert_eq!(extracted_name(Format::Zip, "../x").as_deref(), Some("x"));
        assert_eq!(
            extracted_name(Format::Zip, "/etc/./passwd").as_deref(),
            Some("etc/passwd")
        );
        assert_eq!(
            extracted_name(Format::Zip, "a\\..\\b").as_deref(),
            Some("a/b")
        );
        assert_eq!(
            extracted_name(Format::Rar, "dir/sub/f.txt").as_deref(),
            Some("f.txt")
        );
        assert_eq!(extracted_name(Format::Zip, "../"), None);
    }

    #[test]
    fn riskier_kinds_come_first() {
        let mut paths = vec!["a.txt", "b.pdf", "c.js", "d.exe", "e.lnk", "f.txt"];
        paths.sort_by_key(|p| priority(p));
        assert_eq!(paths, ["e.lnk", "d.exe", "c.js", "b.pdf", "a.txt", "f.txt"]);
    }

    #[test]
    fn xlsx_exclusions_follow_unzip() {
        assert!(excluded_from_xlsx("xl/activeX/activeX1.bin"));
        assert!(excluded_from_xlsx("xl/activeX/_rels/activeX1.bin.rels"));
        assert!(excluded_from_xlsx("xl/ctrlProps/ctrlProp1.xml"));
        assert!(!excluded_from_xlsx("xl/workbook.xml"));
    }
}
