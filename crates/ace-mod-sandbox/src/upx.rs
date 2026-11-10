//! ace3's `UPXAnalyzer` (`saq/modules/file_analysis/upx.py`): `upx -t` tests a PE file and, when
//! it's UPX packed, `upx -d` unpacks it, in the sandbox runner.

use std::time::Duration;

use ace_mod_files::checks::is_pe_file;
use ace_results::types::executables::UpxAnalysis;
use ace_results::{ObservableKind, Relationship, RelationshipKind, ResultEnvelope, YaraMeta};
use ace_sdk::tools::ToolRun;
use ace_sdk::{Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use regex::Regex;

use crate::{copy_directives, head, name_fits, source, stopped_reason};

/// The upx module.
pub struct UpxAnalyzer {
    ok: Regex,
}

impl Module for UpxAnalyzer {
    const NAME: &'static str = "upx";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const TOOLS: &'static [&'static str] = &["upx"];
    /// ace3's `maximum_analysis_time`, 60 s, which each run's timeout comes from: ace3's module
    /// gives upx none of its own.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        memory_mb: 512,
        cpu_seconds: 60,
    };
    type Output = UpxAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(UpxAnalyzer {
            // ace3's pattern, with re.M
            ok: Regex::new(r"(?m)^testing .* \[OK\]$").map_err(ModuleError::other)?,
        })
    }
}

impl Parser for UpxAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<UpxAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        if !is_pe_file(&head(&file.local_path, 2)?) {
            return Ok(Outcome::Skipped("not a PE file".to_owned()));
        }
        let local = file.local_path.display().to_string();
        // the time left, as ace3's run_sandboxed_tool gives a run with no timeout of its own
        let unbounded = ctx.time_left();
        let test = ToolRun::new("upx", ["-t", local.as_str()])
            .read(&file.local_path)
            .timeout(unbounded);
        let output = ctx.run_tool(test)?;
        if output.stopped().is_some() {
            return Ok(Outcome::Skipped(format!(
                "upx -t did not finish: {}",
                stopped_reason(&output)
            )));
        }
        if !self.ok.is_match(&output.stdout_text()) {
            return Ok(Outcome::Skipped("not packed by UPX".to_owned()));
        }

        let mut result = ResultEnvelope::new(UpxAnalysis::default());
        let target = format!("{}.upx.exe", file.path);
        let unpack = ToolRun::new("upx", ["-d", "-ounpacked.exe", local.as_str()])
            .read(&file.local_path)
            .keep("unpacked.exe")
            .timeout(ctx.time_left());
        let output = ctx.run_tool(unpack)?;
        if output.stopped().is_some() {
            // whatever it wrote is incomplete, and wasn't kept
            result.details.error = Some(format!(
                "upx -d did not finish: {}",
                stopped_reason(&output)
            ));
            result.summary = Some(summary(&result.details));
            return Ok(Outcome::Done(result));
        }
        result.details.stdout = Some(output.stdout_text());
        result.details.stderr = Some(output.stderr_text());
        result.details.output_file = Some(format!("{}.upx.exe", file.name()));
        result.summary = Some(summary(&result.details));
        if let Some(unpacked) = output.output("unpacked.exe")
            && name_fits(&target)
        {
            let mut new_file = ctx.write_file_from(
                &target,
                &mut std::fs::File::open(unpacked)?,
                &[YaraMeta::new("type", "executable.unpacked").map_err(ModuleError::other)?],
            )?;
            new_file.relationships.push(Relationship::new(
                RelationshipKind::ExtractedFrom,
                source(file),
            ));
            new_file.tags.push("upx".to_owned());
            copy_directives(ctx.observable(), file, &mut new_file);
            result.files.push(new_file);
        }
        Ok(Outcome::Done(result))
    }
}

/// `UPXAnalysis.generate_summary`.
fn summary(details: &UpxAnalysis) -> String {
    match &details.error {
        Some(error) if !error.is_empty() => {
            format!("UPX Analysis: decompression failed: {error}")
        }
        _ => format!(
            "UPX Analysis: decompression success: {}",
            details.output_file.as_deref().unwrap_or("None")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upx_tests_ok_on_a_line_of_its_own() {
        let module = UpxAnalyzer::init(&()).unwrap();
        assert!(
            module
                .ok
                .is_match("UPX 4.2.4\n\ntesting /a/b.exe [OK]\n\nTested 1 file.\n")
        );
        assert!(!module.ok.is_match("testing a.exe [OK] and more\n"));
        assert!(!module.ok.is_match("upx: a.exe: NotPackedException\n"));
    }
}
