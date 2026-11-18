//! ace3's `ExifAnalyzer` (`saq/modules/file_analysis/exif.py`): ExifTool's metadata of an Office
//! document, an OLE file or a PDF, in the details and pretty-printed in a file for YARA, run in the
//! sandbox runner.
//!
//! ace3 runs `exiftool -j -G -n <file>` on the file where the alert keeps it. Here the runner copies
//! it into the tool's working directory under the file's own name, so ExifTool's `File:FileName` is
//! the same; `SourceFile`, `File:Directory` and the file's dates are this run's.

use std::time::Duration;

use ace_mod_files::checks::{is_office_ext, is_ole_file, is_pdf_file};
use ace_pycompat::json::{Value, loads};
use ace_results::types::file_type::FileTypeAnalysis;
use ace_results::types::sandbox::ExifAnalysis;
use ace_results::{ObservableKind, Relationship, RelationshipKind, ResultEnvelope, YaraMeta};
use ace_sdk::takes::{Case, Condition, Takes, Text};
use ace_sdk::tools::{ToolOutput, ToolRun, is_plain_name};
use ace_sdk::{InputFile, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::pprint::{pformat, py_str, repr};
use crate::{head, name_fits};

/// ace3's section of the module.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ExifSettings {
    /// Seconds one exiftool run may take before the file is recorded as timed out.
    pub timeout: u64,
    /// The largest file analyzed, ace3's `file_size_limit`, in bytes.
    pub file_size_limit: u64,
}

impl Default for ExifSettings {
    /// ace3's `saq.default.yaml`.
    fn default() -> Self {
        ExifSettings {
            timeout: 30,
            file_size_limit: 80 * 1024 * 1024,
        }
    }
}

/// The exif module.
pub struct ExifAnalyzer;

impl Module for ExifAnalyzer {
    const NAME: &'static str = "exif";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    /// ace3's module reads file_type's result if it's there, its wait for it commented out
    /// (`exif.py:169`). Here it always is.
    const DEPENDS_ON: &'static [&'static str] = &["file_type"];
    const TOOLS: &'static [&'static str] = &["exiftool"];
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(120),
        memory_mb: 1024,
        cpu_seconds: 120,
    };
    type Output = ExifAnalysis;
    type Settings = ExifSettings;

    fn init(_: &ExifSettings) -> Result<Self, ModuleError> {
        Ok(ExifAnalyzer)
    }

    fn takes(settings: &ExifSettings) -> Takes {
        let takes = Takes::everything()
            .and(
                Condition::Path(Text::ends_with(".pdfparser", Case::Exact)).negated(),
                "pdfparser output",
            )
            .and(
                Condition::Path(Text::ends_with(".gs.pdf", Case::Exact)).negated(),
                "Ghostscript output",
            );
        // a limit of 0 is none
        if settings.file_size_limit > 0 {
            return takes.and(
                Condition::at_most(settings.file_size_limit),
                "larger than file_size_limit",
            );
        }
        takes
    }
}

/// `is_office_file`: an Office extension, or file_type's description naming an Office format.
fn is_office_file(file: &InputFile, file_type: Option<&FileTypeAnalysis>) -> bool {
    let mut result = is_office_ext(file.name());
    if let Some(analysis) = file_type {
        let description = analysis.file_type.to_lowercase();
        result |= [
            "microsoft powerpoint",
            "microsoft excel",
            "microsoft word",
            "microsoft ooxml",
            "opendocument",
        ]
        .iter()
        .any(|kind| description.contains(kind));
    }
    result
}

/// `_read_metadata`: exiftool's one object, or why its output isn't one.
fn read_metadata(stdout: &str) -> Result<Value, String> {
    let mut metadata = loads(stdout).map_err(|e| e.to_string())?;
    if let Value::Array(items) = &mut metadata
        && items.len() == 1
        && matches!(items[0], Value::Object(_))
    {
        return Ok(items.remove(0));
    }
    let shown: String = repr(&metadata).chars().take(100).collect();
    Err(format!("expected a list holding one object, not {shown}"))
}

/// `_failure_reason`.
fn failure_reason(output: &ToolOutput, returncode: i32) -> String {
    if let Ok(metadata) = read_metadata(&output.stdout_text())
        && let Some(reason) = metadata.get("ExifTool:Error")
        && is_truthy(reason)
    {
        return py_str(reason);
    }
    let stderr = output.stderr_text();
    if let Some(last) = ace_pycompat::pystr::splitlines(ace_pycompat::pystr::strip(&stderr)).last()
    {
        return last.chars().take(500).collect();
    }
    // ace3's sandbox exits 128 + N for a command killed by signal N, up to SIGRTMAX
    if 128 < returncode && returncode <= 128 + 64 {
        return format!("exiftool was killed by signal {}", returncode - 128);
    }
    format!("exiftool exited with status {returncode}")
}

fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Int(digits) => !digits
            .trim_start_matches('-')
            .trim_start_matches('0')
            .is_empty(),
        Value::Float(f) => *f != 0.0,
        Value::Str(s) => !s.as_str().is_empty() || s.has_surrogates(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(members) => !members.is_empty(),
    }
}

/// `format_item_list_for_summary`.
fn item_list(items: &[String]) -> String {
    let mut result = items
        .iter()
        .take(20)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if items.len() > 20 {
        result.push_str(&format!(" + {} more", items.len() - 20));
    }
    result
}

/// `ExifAnalysis.generate_summary`, for metadata exiftool printed.
fn summary(metadata: &Value) -> String {
    let mut parts = Vec::new();
    if let Value::Object(members) = metadata {
        for (key, value) in members {
            let key = key.as_str();
            if key.starts_with("ExifTool:")
                || key.starts_with("SourceFile")
                || key.starts_with("File:")
            {
                continue;
            }
            let key = key.split_once(':').map_or(key, |(_, rest)| rest);
            parts.push(format!("{key}={}", py_str(value)));
        }
    }
    format!("Exiftool Analysis: {}", item_list(&parts))
}

const DISPLAY_NAME: &str = "Exiftool Analysis";

impl Parser for ExifAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<ExifSettings>,
    ) -> Result<Outcome<ExifAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let path = file.path.as_str();
        let file_type = ctx.dependency_result::<FileTypeAnalysis>()?;
        let start = head(&file.local_path, 1024)?;
        if !is_office_file(file, file_type.as_ref())
            && !is_ole_file(&start)
            && !is_pdf_file(path, &start)
        {
            return Ok(Outcome::Skipped(
                "not an Office document or a PDF".to_owned(),
            ));
        }
        let mut result = ResultEnvelope::new(ExifAnalysis::default());
        let name = if is_plain_name(file.name()) {
            file.name()
        } else {
            "input"
        };
        let run = ToolRun::new("exiftool", ["-j", "-G", "-n", name])
            .stage(&file.local_path, name)
            .timeout(Duration::from_secs(ctx.settings().timeout));
        let output = ctx.run_tool(run)?;
        let Some(returncode) = output.returncode() else {
            result.error = Some("exiftool did not finish".to_owned());
            result.summary = Some(format!("{DISPLAY_NAME}: ⚠ exiftool did not finish"));
            return Ok(Outcome::Done(result));
        };
        if returncode != 0 {
            let reason = failure_reason(&output, returncode);
            tracing::info!(%reason, "exif data extraction failed");
            result.summary = Some(format!("{DISPLAY_NAME}: ⚠ {reason}"));
            result.error = Some(reason);
            return Ok(Outcome::Done(result));
        }
        let stdout = output.stdout_text();
        let metadata = match read_metadata(&stdout) {
            Ok(metadata) => metadata,
            Err(e) => {
                let reason = format!("unreadable exiftool output: {e}");
                result.summary = Some(format!("{DISPLAY_NAME}: ⚠ {reason}"));
                result.error = Some(reason);
                return Ok(Outcome::Done(result));
            }
        };
        // the details hold the same object, as JSON keeps it
        if let Some(serde_json::Value::Array(items)) =
            serde_json::from_str::<serde_json::Value>(&stdout).ok()
            && let Some(serde_json::Value::Object(object)) = items.into_iter().next()
        {
            result.details.exifdata = object;
        }
        // pformat recurses once a level, and ace3 writes repr's one line past its recursion limit
        let text = pformat(&metadata).unwrap_or_else(|| {
            tracing::info!("exiftool's metadata is nested too deeply to pretty print");
            repr(&metadata)
        });
        let target_dir = format!("{path}.exif");
        let target = format!("{target_dir}/exiftool.out");
        result.summary = Some(summary(&metadata));
        if name_fits(&target_dir) {
            result.details.output_dir = Some(target_dir);
            let mut new_file = ctx.write_file(
                &target,
                text.as_bytes(),
                &[YaraMeta::new("type", "metadata.exif").map_err(ModuleError::other)?],
            )?;
            new_file.relationships.push(Relationship::new(
                RelationshipKind::ExtractedFrom,
                crate::source(file),
            ));
            new_file
                .exclude_modules
                .push("file_hash_analyzer".to_owned());
            new_file.exclude_modules.push("file_type".to_owned());
            result.files.push(new_file);
        }
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_summary_leaves_out_exiftools_own_and_the_files_keys() {
        let metadata = loads(
            r#"{"SourceFile": "a.pdf", "ExifTool:ExifToolVersion": 13.25, "File:FileName": "a.pdf",
                "PDF:PDFVersion": 1.4, "PDF:Linearized": false, "PDF:PageCount": 2}"#,
        )
        .unwrap();
        assert_eq!(
            summary(&metadata),
            "Exiftool Analysis: PDFVersion=1.4, Linearized=False, PageCount=2"
        );
    }

    #[test]
    fn exiftools_output_is_one_object() {
        assert!(read_metadata("[{\"a\": 1}]").is_ok());
        assert_eq!(
            read_metadata("[1, 2]").unwrap_err(),
            "expected a list holding one object, not [1, 2]"
        );
    }
}
