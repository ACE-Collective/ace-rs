//! ace3's `ExtractedRTFAnalyzer` and `NoWhiteSpaceAnalyzer` (`saq/modules/file_analysis/rtf.py`),
//! the two modules of that file beside `rtfole`, which `ace-mod-oletools` ports.
//!
//! `extracted_rtf_analyzer` looks at a file `rtfole` wrote out of an RTF's objects. ace3 knows one
//! by the `extracted_rtf` tag, which only rtfole gives, as it adds the file; ace-rs's core tells the
//! module which modules' results added its file, for its declaration (`takes::Condition::AddedBy`),
//! so it looks for rtfole's name there. Its file is first leased once nothing nearer the root is pending (PLAN.md
//! decision 15), so rtfole's result, on the RTF above it, has landed by then. Each suspect
//! extension, mime type or file type file_type found is a detection, and sends the file to the
//! sandbox.
//!
//! `nowhitespace_analyzer` writes a copy of an RTF file without its ASCII whitespace,
//! `<file>.nowhitespace`, for YARA to scan.

use std::fs::File;
use std::io::{self, BufReader, Read};

use ace_pycompat::pystr::{lower, strip};
use ace_results::FileRole;
use ace_results::types::file_type::FileTypeAnalysis;
use ace_results::types::rtf::RtfOleObjectAnalysis;
use ace_results::types::scripts::{ExtractedRtfAnalysis, NoWhiteSpaceAnalysis};
use ace_results::{AnalysisType, Detection, ObservableKind, ResultEnvelope};
use ace_sdk::takes::{Case, Condition, Takes, Text, TypeFact};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{DIRECTIVE_SANDBOX, name_fits, name_too_long, source};

/// `extracted_rtf_analyzer`'s manifest.
pub const EXTRACTED_RTF_MANIFEST: Manifest = Manifest::parser::<ExtractedRtfAnalyzer>();
/// `nowhitespace_analyzer`'s manifest.
pub const NOWHITESPACE_MANIFEST: Manifest = Manifest::parser::<NoWhiteSpaceAnalyzer>();

/// ace3's built-in `RTF_EXTRACTED_SUSPECT_FILE` signature.
const RTF_EXTRACTED_SUSPECT_FILE: &str = "cb9764d5-049b-4b7e-bf40-cf7e9c618058";
const NOWHITESPACE_SUFFIX: &str = ".nowhitespace";
/// `bytes.translate(None, delete=b' \t\r\n\f\v')`.
const WHITESPACE: &[u8] = b" \t\r\n\x0c\x0b";

/// ace3's settings of `extracted_rtf_analyzer`: comma-separated lists.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ExtractedRtfSettings {
    /// Extensions that make a file suspect.
    pub suspect_ext: String,
    /// Text that makes a file suspect when file_type's mime type holds it.
    pub suspect_mime_type: String,
    /// Text that makes a file suspect when file_type's description holds it.
    pub suspect_file_type: String,
}

impl Default for ExtractedRtfSettings {
    fn default() -> Self {
        ExtractedRtfSettings {
            suspect_ext: "js,jse,vbs,vbe,ps1,exe,jar,zip,lnk".to_owned(),
            suspect_mime_type: "application/x-dosexec".to_owned(),
            suspect_file_type: "PE32 executable,MS Windows shortcut".to_owned(),
        }
    }
}

pub struct ExtractedRtfAnalyzer;

impl Module for ExtractedRtfAnalyzer {
    const NAME: &'static str = ExtractedRtfAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const DEPENDS_ON: &'static [&'static str] = &[FileTypeAnalysis::MODULE];
    const RESOURCES: Resources = crate::RESOURCES;
    type Output = ExtractedRtfAnalysis;
    type Settings = ExtractedRtfSettings;

    fn init(_: &ExtractedRtfSettings) -> Result<Self, ModuleError> {
        Ok(ExtractedRtfAnalyzer)
    }

    fn takes(_: &ExtractedRtfSettings) -> Takes {
        Takes::everything()
            .and(
                Condition::added_by(RtfOleObjectAnalysis::MODULE),
                "not an output of rtfole",
            )
            .and(
                Condition::HasResult(FileTypeAnalysis::MODULE.to_owned()),
                "no file type analysis",
            )
    }
}

/// The detections a file at `path` gets, in ace3's order, each once.
pub fn suspicions(
    settings: &ExtractedRtfSettings,
    path: &str,
    file_type: &FileTypeAnalysis,
) -> Vec<&'static str> {
    let mut found = Vec::new();
    let mut add = |description| {
        if !found.contains(&description) {
            found.push(description);
        }
    };
    let lower_path = lower(path);
    for ext in settings.suspect_ext.split(',').map(strip) {
        if lower_path.ends_with(&format!(".{ext}")) {
            add("file extracted from RTF has suspect file extension");
        }
    }
    let mime = lower(&file_type.mime);
    for mime_type in settings.suspect_mime_type.split(',').map(strip) {
        if mime.contains(lower(mime_type).as_ref()) {
            add("file extracted from RTF has suspect mime type");
        }
    }
    let description = lower(&file_type.file_type);
    for suspect in settings.suspect_file_type.split(',').map(strip) {
        if description.contains(lower(suspect).as_ref()) {
            add("file extracted from RTF has suspect file type");
        }
    }
    found
}

impl Parser for ExtractedRtfAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<ExtractedRtfSettings>,
    ) -> Result<Outcome<ExtractedRtfAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let Some(file_type) = ctx.dependency_result::<FileTypeAnalysis>()? else {
            return Ok(Outcome::Skipped("no file type analysis".to_owned()));
        };
        let mut result = ResultEnvelope::new(ExtractedRtfAnalysis {});
        for description in suspicions(ctx.settings(), file.path.as_str(), &file_type) {
            result
                .analyzed
                .detections
                .push(Detection::new(description).with_signature(RTF_EXTRACTED_SUSPECT_FILE));
            result.analyzed.add_directive(DIRECTIVE_SANDBOX);
        }
        Ok(Outcome::Done(result))
    }
}

pub struct NoWhiteSpaceAnalyzer;

impl Module for NoWhiteSpaceAnalyzer {
    const NAME: &'static str = NoWhiteSpaceAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const RESOURCES: Resources = crate::RESOURCES;
    type Output = NoWhiteSpaceAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(NoWhiteSpaceAnalyzer)
    }

    fn takes(_: &()) -> Takes {
        Takes::everything()
            .and(
                Condition::Path(Text::ends_with(NOWHITESPACE_SUFFIX, Case::Exact)).negated(),
                "already without whitespace",
            )
            .and(Condition::not_empty(), "an empty file")
            // `\rt` or `{\rt` first, from the file's type (PLAN.md decision 25)
            .and(Condition::type_fact(TypeFact::IsRtfFile), "not an RTF file")
    }
}

/// A reader of `inner` without its whitespace, counting what it leaves out.
struct Stripped<R> {
    inner: R,
    removed: u64,
}

impl<R: Read> Read for Stripped<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = self.inner.read(buf)?;
            if n == 0 {
                return Ok(0);
            }
            let mut kept = 0;
            for i in 0..n {
                if WHITESPACE.contains(&buf[i]) {
                    self.removed += 1;
                } else {
                    buf[kept] = buf[i];
                    kept += 1;
                }
            }
            // a read of only whitespace isn't the end of the file
            if kept > 0 {
                return Ok(kept);
            }
        }
    }
}

/// `display_name`, which ace3's class doesn't override: the class's name.
fn nowhitespace_summary(count: u64) -> Option<String> {
    (count > 0)
        .then(|| format!("NoWhiteSpaceAnalysis: Ignore Whitespace Characters ({count} removed)"))
}

impl Parser for NoWhiteSpaceAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<NoWhiteSpaceAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let path = file.path.as_str();
        let mut result = ResultEnvelope::new(NoWhiteSpaceAnalysis::default());
        if name_fits(file, NOWHITESPACE_SUFFIX) {
            let mut stripped = Stripped {
                inner: BufReader::with_capacity(1024 * 1024, File::open(&file.local_path)?),
                removed: 0,
            };
            let mut output = ctx.write_file_from(
                &format!("{path}{NOWHITESPACE_SUFFIX}"),
                &mut stripped,
                FileRole::DOCUMENT_RTF_STRIPPED,
            )?;
            output.redirection = Some(source(file));
            result.files.push(output);
            result.details.count = stripped.removed;
        } else {
            result.error = Some(name_too_long(file, NOWHITESPACE_SUFFIX));
        }
        result.summary = nowhitespace_summary(result.details.count);
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_type(description: &str, mime: &str) -> FileTypeAnalysis {
        FileTypeAnalysis {
            file_type: description.to_owned(),
            mime: mime.to_owned(),
            ..FileTypeAnalysis::default()
        }
    }

    #[test]
    fn a_file_is_suspect_by_extension_mime_type_and_file_type() {
        let settings = ExtractedRtfSettings::default();
        assert_eq!(
            suspicions(
                &settings,
                "a.rtf.rtfobj/a.rtf_X.EXE",
                &file_type("PE32 executable (GUI)", "application/x-dosexec")
            ),
            [
                "file extracted from RTF has suspect file extension",
                "file extracted from RTF has suspect mime type",
                "file extracted from RTF has suspect file type",
            ]
        );
        assert!(suspicions(&settings, "a.txt", &file_type("ASCII text", "text/plain")).is_empty());
    }

    #[test]
    fn whitespace_is_left_out_and_counted() {
        let mut stripped = Stripped {
            inner: &b"{\\rtf1 a\tb\r\n\x0c\x0b}   "[..],
            removed: 0,
        };
        let mut out = Vec::new();
        stripped.read_to_end(&mut out).expect("reads");
        assert_eq!(out, b"{\\rtf1ab}");
        assert_eq!(stripped.removed, 9);
        assert_eq!(nowhitespace_summary(0), None);
    }
}
