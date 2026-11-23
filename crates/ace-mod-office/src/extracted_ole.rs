//! `extracted_ole_analyzer`: ace3's `ExtractedOLEAnalyzer` (`saq/modules/file_analysis/ole.py`).
//!
//! A file an `officeparser3` result added gets a result here, and is suspect when file_type's
//! description holds one of `suspect_file_type`, when its path ends in one of `suspect_file_ext`,
//! or failing both when `node --check` accepts it and it reads like JavaScript (file_type's own
//! check, `ace_mod_files::javascript`). A suspect file gets a detection and the
//! `suspect_ole_attachment` tag.
//!
//! Where ace-rs departs: ace3 asks which analyses hold the file when it runs, in the pass after
//! officeparser3 added it. ace-rs's core tells the module which modules' results added the file, as
//! they are when the task is leased, so the module runs once everything else in the root has
//! finished, by when officeparser3's result has landed even where another module added the same
//! bytes first. The file's path is the one the core kept, which is the first module's to land
//! (PLAN.md 7.5 batch 5's note on the race).

use ace_mod_files::javascript::is_javascript_file;
use ace_results::types::file_type::FileTypeAnalysis;
use ace_results::types::office::{ExtractedOleAnalysis, OfficeParserAnalysis};
use ace_results::{AnalysisType, Detection, ObservableKind, ResultEnvelope};
use ace_sdk::takes::{Condition, Takes};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::item_list;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<ExtractedOleAnalyzer>();

/// ace3's built-in `OLE_EXTRACTED_SUSPECT_FILE` signature.
const OLE_EXTRACTED_SUSPECT_FILE: &str = "827c5aab-9fa2-45d9-8c5e-a13cd1be9812";
const DISPLAY_NAME: &str = "Extracted OLE Analysis";

/// ace3's settings of the module: comma-separated lists.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ExtractedOleSettings {
    /// Text that makes a file suspect when file_type's description holds it.
    pub suspect_file_type: String,
    /// Extensions that make a file suspect.
    pub suspect_file_ext: String,
}

impl Default for ExtractedOleSettings {
    fn default() -> Self {
        ExtractedOleSettings {
            suspect_file_type: "ms windows shortcut".to_owned(),
            suspect_file_ext: "vbs,jse,exe,jar,lnk,ps1,bat,scr,hta,wsf,cmd,vbe,wsc".to_owned(),
        }
    }
}

pub struct ExtractedOleAnalyzer;

/// Why a file is suspect, as ace3's detection says it, or `None`.
pub fn suspicion(
    settings: &ExtractedOleSettings,
    path: &str,
    file_type: &str,
    data: &[u8],
) -> Option<String> {
    use ace_pycompat::pystr::{lower, strip};
    let file_type = lower(file_type);
    for suspect in settings.suspect_file_type.split(',').map(strip) {
        if file_type.contains(lower(strip(suspect)).as_ref()) {
            return Some(format!("OLE attachment has suspect file type {suspect}"));
        }
    }
    let lower_path = lower(path);
    for ext in settings.suspect_file_ext.split(',').map(strip) {
        if lower_path.ends_with(&format!(".{ext}")) {
            return Some(format!("OLE attachment has suspect file ext {ext}"));
        }
    }
    is_javascript_file(path, data).then(|| format!("OLE attachment {path} is a javascript file"))
}

impl Module for ExtractedOleAnalyzer {
    const NAME: &'static str = ExtractedOleAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const DEPENDS_ON: &'static [&'static str] = &[FileTypeAnalysis::MODULE];
    const RUNS_LAST: bool = true;
    type Output = ExtractedOleAnalysis;
    type Settings = ExtractedOleSettings;

    fn init(_: &ExtractedOleSettings) -> Result<Self, ModuleError> {
        Ok(ExtractedOleAnalyzer)
    }

    fn takes(_: &ExtractedOleSettings) -> Takes {
        Takes::everything()
            .and(
                Condition::HasResult(FileTypeAnalysis::MODULE.to_owned()),
                "no file type analysis",
            )
            .and(
                Condition::added_by(OfficeParserAnalysis::MODULE),
                "not an output of officeparser3",
            )
    }
}

impl Parser for ExtractedOleAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<ExtractedOleSettings>,
    ) -> Result<Outcome<ExtractedOleAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let Some(file_type) = ctx.dependency_result::<FileTypeAnalysis>()? else {
            return Ok(Outcome::Skipped("no file type analysis".to_owned()));
        };
        let data = std::fs::read(&file.local_path)?;
        let path = file.path.as_str();
        let mut result = ResultEnvelope::new(ExtractedOleAnalysis::default());
        if let Some(why) = suspicion(ctx.settings(), path, &file_type.file_type, &data) {
            result
                .analyzed
                .detections
                .push(Detection::new(why).with_signature(OLE_EXTRACTED_SUSPECT_FILE));
            result.analyzed.add_tag("suspect_ole_attachment");
            result.details.suspect_files.push(path.to_owned());
            result.summary = Some(format!(
                "{DISPLAY_NAME}: identified ({}) as suspect files",
                item_list(&result.details.suspect_files)
            ));
        }
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_is_suspect_by_type_then_extension_then_javascript() {
        let settings = ExtractedOleSettings::default();
        assert_eq!(
            suspicion(
                &settings,
                "a.vbs",
                "MS Windows shortcut, Item id list present",
                b"x"
            ),
            Some("OLE attachment has suspect file type ms windows shortcut".to_owned())
        );
        assert_eq!(
            suspicion(&settings, "d/A.EXE", "data", b"x"),
            Some("OLE attachment has suspect file ext exe".to_owned())
        );
        assert_eq!(
            suspicion(&settings, "d/s.dat", "ASCII text", b"var x = f();\n"),
            Some("OLE attachment d/s.dat is a javascript file".to_owned())
        );
        assert_eq!(
            suspicion(&settings, "d/t.txt", "ASCII text", b"just words\n"),
            None
        );
    }
}
