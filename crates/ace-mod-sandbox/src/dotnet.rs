//! ace3's `De4dotAnalyzer` and `IlspyAnalyzer` (`saq/modules/file_analysis/dotnet.py`): de4dotEx
//! detects an obfuscator in a .NET assembly and cleans it, and ilspycmd disassembles one to IL, each
//! on .NET 10 in the sandbox runner.
//!
//! ace3 tells a .NET assembly by `file -b -L` naming one (`is_dotnet`), running `file` as a plain
//! process; here libmagic runs in the task over the same database (`ace_mod_files::libmagic`). The
//! tools' heap limit, region range and memory limit are their specs' (`ace_sdk::tools`), ace3's
//! `DOTNET_ENV` and `DOTNET_MEMORY_LIMIT`. ace3 reports a runtime that couldn't start in the sandbox
//! (`DOTNET_STARTUP_ERRORS`) as the node's failure; here the task fails.

use std::fs;
use std::path::Path;
use std::time::Duration;

use ace_mod_files::checks::is_pe_file;
use ace_mod_files::libmagic::{self, Answer, Magic};
use ace_pycompat::pystr::{lstrip, strip};
use ace_results::types::executables::{De4dotAnalysis, IlspyAnalysis};
use ace_results::{ObservableKind, Relationship, RelationshipKind, ResultEnvelope, YaraMeta};
use ace_sdk::tools::{ToolOutput, ToolRun, is_plain_name};
use ace_sdk::{Module, ModuleError, Outcome, Parser, Resources, TaskContext};

use crate::{head, name_fits, source, stopped_reason, tool_failure_reason};

/// ace3's `DE4DOT_TIMEOUT_SECONDS` and `ILSPY_TIMEOUT_SECONDS`.
const TIMEOUT: Duration = Duration::from_secs(10);

/// What the .NET host starts its output with when the sandbox keeps CoreCLR from starting: no
/// `/proc/<pid>`, or too little address space for its GC (`DOTNET_STARTUP_ERRORS`).
const STARTUP_ERRORS: [&str; 2] = ["Failed to create CoreCLR", "GC heap initialization failed"];

/// The task's limits: ace3's `maximum_analysis_time`, 60 s. The runtime runs in the runner, under
/// its own limits; the task holds only what it hands on.
const RESOURCES: Resources = Resources {
    timeout: Duration::from_secs(60),
    memory_mb: 512,
    cpu_seconds: 60,
};

/// libmagic's database, read before containment.
struct Database(Result<Vec<u8>, String>);

impl Database {
    fn read() -> Database {
        Database(fs::read(libmagic::DATABASE).map_err(|e| e.to_string()))
    }

    /// `is_dotnet`: a PE file that `file -b -L` calls a .NET assembly.
    fn is_dotnet(&self, local: &Path) -> Result<bool, ModuleError> {
        if !is_pe_file(&head(local, 2)?) {
            return Ok(false);
        }
        let database = self
            .0
            .as_ref()
            .map_err(|e| ModuleError::other(format!("{}: {e}", libmagic::DATABASE)))?;
        let magic = Magic::load(database, Answer::Description).map_err(ModuleError::other)?;
        let description = magic.file(local);
        // `file` writes its own errors to stdout, which ace3 reads as an answer like any other
        Ok(description.to_lowercase().contains(".net assembly"))
    }
}

/// Fails the task when the runtime couldn't start, as ace3 reports such a tool as the node's.
fn check_started(tool: &str, output: &ToolOutput) -> Result<(), ModuleError> {
    let Some(code) = output.returncode() else {
        return Ok(());
    };
    let (stdout, stderr) = (output.stdout_text(), output.stderr_text());
    if code != 0
        && STARTUP_ERRORS
            .iter()
            .any(|e| lstrip(&stdout).starts_with(e) || lstrip(&stderr).starts_with(e))
    {
        let shown: String = strip(if strip(&stdout).is_empty() {
            &stderr
        } else {
            &stdout
        })
        .chars()
        .take(500)
        .collect();
        return Err(ModuleError::other(format!(
            "{tool} can't start in the sandbox: {shown}"
        )));
    }
    Ok(())
}

/// The de4dot module.
pub struct De4dotAnalyzer {
    database: Database,
}

impl Module for De4dotAnalyzer {
    const NAME: &'static str = "de4dot";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const TOOLS: &'static [&'static str] = &["de4dot"];
    const RESOURCES: Resources = RESOURCES;
    type Output = De4dotAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(De4dotAnalyzer {
            database: Database::read(),
        })
    }
}

impl Parser for De4dotAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<De4dotAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        if !self.database.is_dotnet(&file.local_path)? {
            return Ok(Outcome::Skipped("not a .NET assembly".to_owned()));
        }
        let local = file.local_path.display().to_string();
        // check for obfuscation with -d first; de4dot's dynamic string decrypters can call the
        // sample's own methods, which is why it runs in the runner at all
        let detect = ToolRun::new("de4dot", ["-d", local.as_str()])
            .read(&file.local_path)
            .timeout(TIMEOUT);
        let output = ctx.run_tool(detect)?;
        check_started("de4dot", &output)?;
        if output.stopped().is_some() {
            return Ok(Outcome::Skipped(format!(
                "de4dot -d did not finish: {}",
                stopped_reason(&output)
            )));
        }
        if !output.stdout_text().contains("Detected") {
            return Ok(Outcome::Skipped("no obfuscation detected".to_owned()));
        }

        let mut result = ResultEnvelope::new(De4dotAnalysis::default());
        let clean = ToolRun::new("de4dot", [local.as_str(), "-o", "deobfuscated"])
            .read(&file.local_path)
            .keep("deobfuscated")
            .timeout(TIMEOUT);
        let output = ctx.run_tool(clean)?;
        check_started("de4dot", &output)?;
        match output.returncode() {
            None => {
                result.error = Some(format!(
                    "de4dot did not finish: {}",
                    stopped_reason(&output)
                ));
            }
            Some(returncode) => {
                let stderr = output.stderr_text();
                // a run that ended without writing the file failed, however it exited
                if output.output("deobfuscated").is_none() {
                    let error = format!(
                        "{}, without writing a deobfuscated file",
                        tool_failure_reason("de4dot", returncode, &stderr)
                    );
                    tracing::info!("de4dot failed: {error}");
                    result.error = Some(error);
                }
                result.details.stdout = Some(output.stdout_text()).filter(|s| !s.is_empty());
                result.details.stderr = Some(stderr).filter(|s| !s.is_empty());
            }
        }
        // ace3 sets it whether or not the run finished (dotnet.py:146)
        result.details.deobfuscated = true;
        result.summary = Some(match &result.error {
            Some(error) => format!("De4dot Analysis error: {error}"),
            None => "De4dot Analysis: deobfuscated".to_owned(),
        });
        let target = format!("{}.deobfuscated", file.path);
        if let Some(cleaned) = output.output("deobfuscated")
            && name_fits(&target)
        {
            let mut new_file = ctx.write_file_from(
                &target,
                &mut fs::File::open(cleaned)?,
                &[YaraMeta::new("type", "executable.dotnet").map_err(ModuleError::other)?],
            )?;
            new_file.relationships.push(Relationship::new(
                RelationshipKind::ExtractedFrom,
                source(file),
            ));
            new_file.redirection = Some(source(file));
            for module in ["de4dot", "file_hash_analyzer", "file_type"] {
                new_file.exclude_modules.push(module.to_owned());
            }
            result.files.push(new_file);
        }
        Ok(Outcome::Done(result))
    }
}

/// The ilspy module.
pub struct IlspyAnalyzer {
    database: Database,
}

impl Module for IlspyAnalyzer {
    const NAME: &'static str = "ilspy";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const TOOLS: &'static [&'static str] = &["ilspycmd"];
    const RESOURCES: Resources = RESOURCES;
    type Output = IlspyAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(IlspyAnalyzer {
            database: Database::read(),
        })
    }
}

/// `os.path.splitext(name)[0]`: the name without its last extension, a leading dot not counting
/// as one.
fn stem(name: &str) -> &str {
    let start = name.len() - name.trim_start_matches('.').len();
    match name[start..].rfind('.') {
        Some(dot) => &name[..start + dot],
        None => name,
    }
}

impl Parser for IlspyAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<IlspyAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        if !self.database.is_dotnet(&file.local_path)? {
            return Ok(Outcome::Skipped("not a .NET assembly".to_owned()));
        }
        // ace3 writes it at the top of the root, counting up from _ilspy_0 past the names the root
        // already holds; a file is analyzed here once
        let target = format!("{}_ilspy.il", file.name());
        let mut result = ResultEnvelope::new(IlspyAnalysis::default());
        // ilspycmd writes its IL named after the assembly's file, as ace3 gives it the file under
        // its own name; one that isn't a plain name is given as `input`
        let name = if is_plain_name(file.name()) {
            file.name()
        } else {
            "input"
        };
        let il_name = format!("{}.il", stem(name));
        let run = ToolRun::new(
            "ilspycmd",
            ["-il", "--disable-updatecheck", "-o", ".", name],
        )
        .stage(&file.local_path, name)
        .keep(&il_name)
        .timeout(TIMEOUT);
        let output = ctx.run_tool(run)?;
        check_started("ilspycmd", &output)?;
        let Some(code) = output.returncode() else {
            let error = format!("ilspy did not finish: {}", stopped_reason(&output));
            result.summary = Some(summary(&result.details, Some(&error)));
            result.error = Some(error);
            return Ok(Outcome::Done(result));
        };
        result.details.exit_code = Some(code);
        let stderr = output.stderr_text();
        result.details.stderr = Some(stderr.clone()).filter(|s| !s.is_empty());
        let Some(il) = output.output(&il_name) else {
            let error = format!(
                "{}, without writing IL",
                tool_failure_reason("ilspy", code, &stderr)
            );
            tracing::info!("ilspy failed: {error}");
            result.summary = Some(summary(&result.details, Some(&error)));
            result.error = Some(error);
            return Ok(Outcome::Done(result));
        };
        result.summary = Some(summary(&result.details, None));
        if name_fits(&target) {
            let mut new_file =
                ctx.write_file_from(
                    &target,
                    &mut fs::File::open(il)?,
                    &[YaraMeta::new("type", "script.dotnet.decompiled")
                        .map_err(ModuleError::other)?],
                )?;
            new_file.relationships.push(Relationship::new(
                RelationshipKind::ExtractedFrom,
                source(file),
            ));
            new_file.redirection = Some(source(file));
            for module in ["ilspy", "file_hash_analyzer", "file_type"] {
                new_file.exclude_modules.push(module.to_owned());
            }
            result.files.push(new_file);
        }
        Ok(Outcome::Done(result))
    }
}

/// `IlspyAnalysis.generate_summary`, with the result's error.
fn summary(details: &IlspyAnalysis, error: Option<&String>) -> String {
    let mut summary = "Ilspy Analysis".to_owned();
    if let Some(error) = error.filter(|e| !e.is_empty()) {
        return format!("{summary}: failed: {error}");
    }
    if let Some(code) = details.exit_code {
        summary.push_str(&format!(": exit code {code}"));
    }
    if let Some(stderr) = details.stderr.as_ref().filter(|s| !s.is_empty()) {
        summary.push_str(&format!(": stderr: {stderr}"));
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stem_is_pythons_splitext() {
        assert_eq!(stem("a.exe"), "a");
        assert_eq!(stem("a.exe.deobfuscated"), "a.exe");
        assert_eq!(stem(".exe"), ".exe");
        assert_eq!(stem("..x.dll"), "..x");
        assert_eq!(stem("noext"), "noext");
    }
}
