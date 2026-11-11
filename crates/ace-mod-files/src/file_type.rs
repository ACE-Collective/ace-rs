//! `file_type`: ace3's `FileTypeAnalyzer` (`saq/modules/file_analysis/file_type.py`).
//!
//! libmagic's description and mime type of the file, as `file -b -L` and
//! `file -b --mime-type -L` print them, and the checks of `is_file_type.py`, which tag the file
//! and give it the `yara_meta` types that type-scoped YARA rules scan by.
//!
//! Where ace4 departs:
//!
//! - libmagic runs in the task, on the database ace3's `file` reads (`libmagic.rs`); ace3 starts
//!   `file` twice. `is_javascript_file` parses with oxc where ace3 starts node (`javascript.rs`).
//! - ace3 also stamps the mime type on the file observable and works out an image's preview size
//!   for its alert page. ace4's core already stores each file's mime type when the file arrives,
//!   from the same libmagic, and its page doesn't scale previews.

use std::fs;
use std::time::Duration;

use ace_results::types::file_type::FileTypeAnalysis;
use ace_results::{AnalysisType, ObservableKind, ResultEnvelope, YaraMeta};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, Resources, TaskContext};

use crate::checks;
use crate::javascript;
use crate::libmagic::{self, Answer, Magic};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<FileType>();

/// `YARA_META_TYPE_BY_DETAIL`, by the check's result.
pub const JAVASCRIPT_MIME_TYPES: &[&str] = &[
    "text/javascript",
    "application/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "text/ecmascript",
];
pub const JAVASCRIPT_EXTENSIONS: &[&str] = &[".js", ".mjs", ".cjs", ".jse"];

/// Whether file_type gives a file at `path`, with these bytes and its mime type, the `yara_meta` type
/// `script.javascript`: the mime type or the name says JavaScript, and node would parse it.
pub fn tags_javascript(path: &str, mime: &str, data: &[u8]) -> bool {
    let lowered = path.rsplit('/').next().unwrap_or(path).to_lowercase();
    let ext = ace_mod_oletools::ftguess::splitext(&lowered).1;
    (JAVASCRIPT_MIME_TYPES.contains(&mime) || JAVASCRIPT_EXTENSIONS.contains(&ext))
        && crate::javascript::is_javascript_file(path, data)
}

/// The module, with libmagic's database read before containment, which can't open it.
pub struct FileType {
    database: Result<Vec<u8>, String>,
}

impl Module for FileType {
    const NAME: &'static str = FileTypeAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    // ace3 gives the module no limits of its own, and `file` and node none either.
    // docs/measurements/javascript-check.md has what a crafted file costs.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(300),
        memory_mb: 2048,
        cpu_seconds: 300,
    };
    type Output = FileTypeAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(FileType {
            database: fs::read(libmagic::DATABASE).map_err(|e| e.to_string()),
        })
    }
}

/// What the checks found, before tags.
pub fn analyze_bytes(path: &str, data: &[u8], file_type: String, mime: String) -> FileTypeAnalysis {
    let is_zip_file;
    let is_jar_file;
    match checks::zip_names(data) {
        Some(names) => {
            is_zip_file = !names.is_empty();
            is_jar_file = is_zip_file && names.iter().any(|n| n == "META-INF/MANIFEST.MF");
        }
        None => {
            is_zip_file = false;
            is_jar_file = false;
        }
    }
    let is_office_ext = checks::is_office_ext(path);
    let is_ole_file = checks::is_ole_file(data);
    let is_rtf_file = checks::is_rtf_file(data);
    let lower = file_type.to_lowercase();
    let is_office_document = is_office_ext
        || [
            "microsoft powerpoint",
            "microsoft excel",
            "microsoft word",
            "microsoft ooxml",
        ]
        .iter()
        .any(|name| lower.contains(name))
        || is_ole_file
        || is_rtf_file;
    FileTypeAnalysis {
        is_office_ext,
        is_ole_file,
        is_rtf_file,
        is_pdf_file: checks::is_pdf_file(path, data),
        is_pe_file: checks::is_pe_file(data),
        is_zip_file,
        is_x509: crate::x509::is_x509(data),
        is_lnk_file: checks::is_lnk_file(data),
        is_jar_file,
        is_email_file: checks::is_email_file(data) || mime == "message/rfc822",
        is_office_document,
        file_type,
        mime,
    }
}

/// The tags and `yara_meta` types the analysis gives the file, in ace3's order.
pub fn additions(
    analysis: &FileTypeAnalysis,
    name: &str,
    path: &str,
    data: &[u8],
) -> (Vec<&'static str>, Vec<&'static str>) {
    let a = analysis;
    let tags = [
        (a.is_office_document, "microsoft_office"),
        (a.is_ole_file, "ole"),
        (a.is_rtf_file, "rtf"),
        (a.is_pdf_file, "pdf"),
        (a.is_pe_file, "executable"),
        (a.is_zip_file, "zip"),
        (a.is_lnk_file, "lnk"),
        (a.is_x509, "x509"),
        (a.is_jar_file, "jar"),
        (a.is_email_file, "email"),
    ]
    .into_iter()
    .filter_map(|(set, tag)| set.then_some(tag))
    .collect();
    let mut types = Vec::new();
    if a.mime.starts_with("image/") {
        types.push("image");
    }
    for (set, kind) in [
        (a.is_pdf_file, "document.pdf"),
        (a.is_rtf_file, "document.rtf"),
        (a.is_pe_file, "executable"),
        (a.is_jar_file, "archive.jar"),
        (a.is_x509, "certificate.x509"),
        (a.is_email_file, "email"),
    ] {
        if set {
            types.push(kind);
        }
    }
    if a.mime == "text/html" || a.mime == "application/xhtml+xml" {
        types.push("document.html");
    }
    // only when the mime type or the name says JavaScript, as ace3 gates node
    let lowered = name.to_lowercase();
    let ext = ace_mod_oletools::ftguess::splitext(&lowered).1;
    if (JAVASCRIPT_MIME_TYPES.contains(&a.mime.as_str()) || JAVASCRIPT_EXTENSIONS.contains(&ext))
        && javascript::is_javascript_file(path, data)
    {
        types.push("script.javascript");
    }
    (tags, types)
}

impl Parser for FileType {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<FileTypeAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let database = self
            .database
            .as_ref()
            .map_err(|e| ModuleError::other(format!("{}: {e}", libmagic::DATABASE)))?;
        let describe = |answer| -> Result<String, ModuleError> {
            let magic = Magic::load(database, answer).map_err(ModuleError::other)?;
            Ok(ace_pycompat::pystr::strip(&magic.file(&file.local_path)).to_owned())
        };
        let file_type = describe(Answer::Description)?;
        let mime = describe(Answer::MimeType)?;
        ctx.check_cancelled()?;
        let data = fs::read(&file.local_path)?;
        let path = file.path.as_str();
        let analysis = analyze_bytes(path, &data, file_type, mime);
        ctx.check_cancelled()?;
        let (tags, types) = additions(&analysis, file.name(), path, &data);

        let summary = analysis.summary();
        let mut result = ResultEnvelope::new(analysis).with_summary(summary);
        for tag in tags {
            result.analyzed.add_tag(tag);
        }
        for kind in types {
            result
                .analyzed
                .add_yara_meta(YaraMeta::new("type", kind).map_err(ModuleError::other)?);
        }
        Ok(Outcome::Done(result))
    }
}
