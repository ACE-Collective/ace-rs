//! ace3's `JavaClassDecompilerAnalysisModule` (`saq/modules/file_analysis/java.py`): CFR 0.151
//! decompiles a Java class file to source, on the JVM in the sandbox runner.
//!
//! The image's `cfr` tool is `java` with ace3's options and CFR's jar (`ace_sdk::tools`), so the
//! module only names the class. ace3 makes the JVM's configuration readable in its sandbox
//! (`jvm_conf_dirs`); here the tool's spec does. ace3 reports a JVM that couldn't start under its
//! memory limit as the node's failure (`JVM_STARTUP_ERRORS`); here the module does the same, failing
//! the task.

use std::time::Duration;

use ace_pycompat::pystr::{lstrip, splitlines_keepends, strip};
use ace_results::types::executables::JavaClassDecompilerAnalysis;
use ace_results::{ObservableKind, ResultEnvelope, YaraMeta};
use ace_sdk::tools::ToolRun;
use ace_sdk::{Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{head, name_fits, stopped_reason, tool_failure_reason};

/// ace3's section of the module.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct JavaClassDecompilerSettings {
    /// Seconds CFR may run.
    pub timeout: u64,
}

impl Default for JavaClassDecompilerSettings {
    /// ace3's `saq.default.yaml`.
    fn default() -> Self {
        JavaClassDecompilerSettings { timeout: 30 }
    }
}

/// The java_class_decompiler module.
pub struct JavaClassDecompiler;

impl Module for JavaClassDecompiler {
    const NAME: &'static str = "java_class_decompiler";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const TOOLS: &'static [&'static str] = &["cfr"];
    /// ace3's `maximum_analysis_time`, 60 s; the JVM runs in the runner, so the task holds only the
    /// source it hands on.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        memory_mb: 512,
        cpu_seconds: 60,
    };
    type Output = JavaClassDecompilerAnalysis;
    type Settings = JavaClassDecompilerSettings;

    fn init(_: &JavaClassDecompilerSettings) -> Result<Self, ModuleError> {
        Ok(JavaClassDecompiler)
    }
}

/// What the JVM starts its output with when the sandbox keeps it from starting: too little address
/// space for its heap, or no readable `java.security` (ace3's `JVM_STARTUP_ERRORS`).
const JVM_STARTUP_ERRORS: [&str; 2] = [
    "Error occurred during initialization of VM",
    "Exception in thread \"main\" java.lang.InternalError: Error loading java.security file",
];

/// `strip_banner`: drops every block from a line starting `/*` to the next line starting ` */`,
/// the comments CFR starts its output with.
pub fn strip_banner(source: &str) -> String {
    let mut kept = String::with_capacity(source.len());
    let mut in_comment = false;
    for line in splitlines_keepends(source) {
        if in_comment {
            in_comment = !line.starts_with(" */");
        } else if line.starts_with("/*") {
            in_comment = true;
        } else {
            kept.push_str(line);
        }
    }
    kept
}

impl Parser for JavaClassDecompiler {
    fn analyze(
        &self,
        ctx: &TaskContext<JavaClassDecompilerSettings>,
    ) -> Result<Outcome<JavaClassDecompilerAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        if file.size == 0 {
            return Ok(Outcome::Skipped("an empty file".to_owned()));
        }
        if head(&file.local_path, 4)? != b"\xca\xfe\xba\xbe" {
            return Ok(Outcome::Skipped("not a Java class file".to_owned()));
        }
        let mut result = ResultEnvelope::new(JavaClassDecompilerAnalysis::default());
        let local = file.local_path.display().to_string();
        let run = ToolRun::new("cfr", [local.as_str()])
            .read(&file.local_path)
            .timeout(Duration::from_secs(ctx.settings().timeout));
        let output = ctx.run_tool(run)?;
        let Some(returncode) = output.returncode() else {
            // java.py raises AnalysisError here and below, which marks its analysis failed
            let reason = format!("cfr did not finish: {}", stopped_reason(&output));
            tracing::warn!(%reason, "the decompiler didn't finish");
            result.error = Some(reason);
            return Ok(Outcome::Done(result));
        };
        let stdout = output.stdout_text();
        let stderr = output.stderr_text();
        if returncode != 0
            && JVM_STARTUP_ERRORS
                .iter()
                .any(|e| lstrip(&stdout).starts_with(e) || lstrip(&stderr).starts_with(e))
        {
            // ace3's run_sandboxed_tool reports this as a program the sandbox can't start
            let shown: String = strip(if strip(&stdout).is_empty() {
                &stderr
            } else {
                &stdout
            })
            .chars()
            .take(500)
            .collect();
            return Err(ModuleError::other(format!(
                "the JVM can't start in the sandbox: {shown}"
            )));
        }
        // cfr exits 0 for a file it can't decompile; anything else is a crash, and its output isn't
        // source
        if returncode != 0 {
            tracing::info!(returncode, "the decompiler failed");
            result.error = Some(tool_failure_reason("cfr", returncode, &stderr));
            return Ok(Outcome::Done(result));
        }
        let source = strip_banner(&stdout);
        if source.is_empty() {
            tracing::info!("the decompiler returned nothing");
            result.error = Some("cfr could not decompile the class file".to_owned());
            return Ok(Outcome::Done(result));
        }
        // ace3 counts up from 0 past the names its root already holds; a file is analyzed here once
        let target = format!("{}-0-decompiled.java", file.path);
        if !name_fits(&target) {
            return Ok(Outcome::Done(result));
        }
        let mut new_file = ctx.write_file(
            &target,
            source.as_bytes(),
            &[YaraMeta::new("type", "script.java.decompiled").map_err(ModuleError::other)?],
        )?;
        new_file.tags.push("decompiled".to_owned());
        result.details.decompiled_files.push(target);
        result.files.push(new_file);
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfrs_banners_are_cut() {
        let source = "/*\n * Decompiled with CFR 0.151.\n */\npackage a;\n/* inline */ int x;\n";
        assert_eq!(strip_banner(source), "package a;\n");
        assert_eq!(strip_banner("class A {}"), "class A {}");
    }
}
