//! The results of PLAN.md 7.5 batch 11's unpackers and decompilers, which `ace-mod-sandbox` writes,
//! with ace3's keys: `JavaClassDecompilerAnalysis` (`saq/modules/file_analysis/java.py`),
//! `UPXAnalysis` (`upx.py`), `AutoItAnalysis` (`autoit.py`), and `De4dotAnalysis` and
//! `IlspyAnalysis` (`dotnet.py`).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of a `java_class_decompiler_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JavaClassDecompilerAnalysis {
    /// The Java source CFR wrote, by its path in the alert: `<file>-0-decompiled.java`. Empty
    /// when CFR gave nothing.
    pub decompiled_files: Vec<String>,
    /// Why the runner stopped CFR, which ace3 only logs. Absent when it ran to its end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped: Option<String>,
}

impl AnalysisType for JavaClassDecompilerAnalysis {
    const NAME: &'static str = "java_class_decompiler_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "java_class_decompiler";
}

/// The details of a `upx_analysis` result, made once `upx -t` passed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpxAnalysis {
    /// What `upx -d` wrote to stdout and stderr.
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    /// The unpacked file's name, `<name>.upx.exe`, set whatever upx's exit status.
    pub output_file: Option<String>,
    /// Why `upx -d` gave nothing: `upx -d did not finish`, and here why the runner stopped it.
    pub error: Option<String>,
}

impl AnalysisType for UpxAnalysis {
    const NAME: &'static str = "upx_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "upx";
}

/// The details of an `auto_it_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AutoItAnalysis {
    /// What `unautoit list` wrote to stdout and stderr.
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    /// Why there are no scripts: a run that didn't finish, and here why the runner stopped it.
    pub error: Option<String>,
    /// The names of the `.au3` scripts unautoit extracted.
    pub scripts: Vec<String>,
    /// Where they went, by its path in the alert: `<file>.autoit`.
    pub output_dir: Option<String>,
}

impl AnalysisType for AutoItAnalysis {
    const NAME: &'static str = "auto_it_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "autoit";
}

/// The details of a `de4dot_analysis` result, made once `de4dot -d` detected an obfuscator.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct De4dotAnalysis {
    /// What the cleaning run wrote to stdout and stderr, None when it wrote nothing.
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    /// `de4dot did not finish`, and here why the runner stopped it.
    pub error: Option<String>,
    /// Always true once the analysis exists, as ace3 sets it whether or not the run finished.
    pub deobfuscated: bool,
}

impl AnalysisType for De4dotAnalysis {
    const NAME: &'static str = "de4dot_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "de4dot";
}

/// The details of an `ilspy_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IlspyAnalysis {
    /// What ilspycmd wrote to stderr, or `ilspy did not finish`, and here why the runner stopped
    /// it. None when it wrote nothing.
    pub stderr: Option<String>,
    /// Its exit status, as ace3's sandbox gives it: 128 plus a signal that killed it. None when it
    /// was stopped.
    pub exit_code: Option<i32>,
}

impl AnalysisType for IlspyAnalysis {
    const NAME: &'static str = "ilspy_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "ilspy";
}
