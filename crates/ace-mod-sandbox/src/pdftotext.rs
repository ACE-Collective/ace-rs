//! ace3's `PDFTextAnalyzer` (`saq/modules/file_analysis/pdf.py`): poppler's `pdftotext` turns a PDF
//! into text for YARA, in the sandbox runner.

use std::time::Duration;

use ace_results::types::sandbox::PdfTextAnalysis;
use ace_results::{ObservableKind, Relationship, RelationshipKind, ResultEnvelope, YaraMeta};
use ace_sdk::tools::ToolRun;
use ace_sdk::{Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{head, name_fits, source};

/// ace3's section of the module, but for `pdftotext_path`: the pool's image names the program.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct PdfTextSettings {
    /// Seconds pdftotext may run.
    pub timeout: u64,
}

impl Default for PdfTextSettings {
    /// ace3's `saq.default.yaml`.
    fn default() -> Self {
        PdfTextSettings { timeout: 5 }
    }
}

/// The pdftotext module.
pub struct PdfTextAnalyzer;

impl Module for PdfTextAnalyzer {
    const NAME: &'static str = "pdftotext";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const TOOLS: &'static [&'static str] = &["pdftotext"];
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        memory_mb: 512,
        cpu_seconds: 60,
    };
    type Output = PdfTextAnalysis;
    type Settings = PdfTextSettings;

    fn init(_: &PdfTextSettings) -> Result<Self, ModuleError> {
        Ok(PdfTextAnalyzer)
    }
}

/// Where ace3 writes the text: `<file>.txt` for a name ending `.pdf`, any case, and `<file>.pdf.txt`
/// for any other.
fn output_path(path: &str) -> String {
    if path.to_lowercase().ends_with(".pdf") {
        format!("{path}.txt")
    } else {
        format!("{path}.pdf.txt")
    }
}

impl Parser for PdfTextAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<PdfTextSettings>,
    ) -> Result<Outcome<PdfTextAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let path = file.path.as_str();
        if !ace_mod_files::checks::is_pdf_file(path, &head(&file.local_path, 1024)?) {
            return Ok(Outcome::Skipped("not a PDF".to_owned()));
        }
        let mut result = ResultEnvelope::new(PdfTextAnalysis::default());
        let local = file.local_path.display().to_string();
        let run = ToolRun::new("pdftotext", [local.as_str(), "output.txt"])
            .read(&file.local_path)
            .keep("output.txt")
            .timeout(Duration::from_secs(ctx.settings().timeout));
        let output = ctx.run_tool(run)?;
        if let Some(stop) = output.stopped() {
            // ace3's run_sandboxed_tool returns nothing for a tool it stopped, and pdf.py marks
            // the analysis failed
            result.error = Some(format!("pdftotext did not finish: {}", stop.describe()));
            return Ok(Outcome::Done(result));
        }
        result.details.stdout = Some(output.stdout_text());
        result.details.stderr = Some(output.stderr_text());
        let target = output_path(path);
        if let Some(text) = output.output("output.txt")
            && name_fits(&target)
        {
            let mut new_file = ctx.write_file_from(
                &target,
                &mut std::fs::File::open(text)?,
                &[YaraMeta::new("type", "document.pdf.text").map_err(ModuleError::other)?],
            )?;
            new_file.redirection = Some(source(file));
            new_file.relationships.push(Relationship::new(
                RelationshipKind::ExtractedFrom,
                source(file),
            ));
            // 7z tends to choke on these, ace3 says
            new_file.exclude_modules.push("archive".to_owned());
            result.details.output_path = Some(new_file.sha256.to_hex());
            result.files.push(new_file);
            result.summary = Some("PDF Text Analysis".to_owned());
        }
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_text_is_named_as_ace3_names_it() {
        assert_eq!(output_path("a.PDF"), "a.PDF.txt");
        assert_eq!(output_path("dir/b"), "dir/b.pdf.txt");
    }
}
