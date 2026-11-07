//! What the core knows about the modules the Python pool runs (PLAN.md 4.1): each one's manifest
//! and analysis type, as a Rust type. So the core's catalog, its eligibility rules and `ace schema
//! export` treat them like any other module, and the core can check their results against the
//! exported schema (4.2) with nothing from Python.
//!
//! A module's code is in `python/ace4_python/modules/`, under the manifest's name, and this crate
//! never runs. To add one: a `Module` here with its analysis type (in `ace_results::types`, as any
//! real module's is), `.module::<M>()` in `ace::python_pool`, and its file and line in
//! `python/ace4_python/registry.py`.

use std::time::Duration;

use ace_results::types::msoffice::MsofficeEncryptionAnalysis;
use ace_results::types::pcode::PCodeAnalysis;
use ace_results::types::xlm::XlmDeobfuscatorAnalysis;
use ace_results::{AnalysisType, ObservableKind};
use ace_sdk::{Manifest, Module, ModuleError, Resources};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A module for testing the pool itself: it reports the process it ran in, and does what the first
/// part of its fqdn says (`python/ace4_python/modules/python_probe.py`). Nothing analyzes anything
/// with it, so it runs only as an instance a test's overlay names.
pub struct PythonProbe;

/// What a probe reports.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeAnalysis {
    /// The worker process the task ran in.
    pub pid: u32,
    pub uid: u32,
    /// How many tasks this process has been given, this one included.
    pub tasks_in_process: u64,
    pub python: String,
    /// The names of the variables in the worker's environment.
    pub environment: Vec<String>,
    /// What the probe's action found.
    #[serde(default)]
    pub note: Option<String>,
}

impl AnalysisType for ProbeAnalysis {
    const NAME: &'static str = "python_probe_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = PythonProbe::NAME;
}

impl Module for PythonProbe {
    const NAME: &'static str = "python_probe";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
    const INSTANCES_ONLY: bool = true;
    // short, so a test of a hung task doesn't wait long
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(5),
        ..Resources::DEFAULT
    };
    type Output = ProbeAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(PythonProbe)
    }
}

pub const PROBE_MANIFEST: Manifest = Manifest::python::<PythonProbe>();

/// ace3's `MSOfficeEncryptionAnalyzer` (`python/ace4_python/modules/msoffice_encryption_analyzer.py`),
/// on msoffcrypto. It reads the carrying email's body for candidate passwords, and tries them with
/// msoffcrypto where ace3 runs John the Ripper.
pub struct MsofficeEncryption;

/// ace3's settings of the module. Its `john_bin_path` is gone: a worker can't start a process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct MsofficeEncryptionSettings {
    /// The shortest password to try.
    pub range_low: usize,
    /// The longest password to try.
    pub range_high: usize,
    /// How much of the email's body to look at.
    pub byte_limit: usize,
    /// The most passwords to try from the email.
    pub list_limit: usize,
}

impl Default for MsofficeEncryptionSettings {
    fn default() -> Self {
        MsofficeEncryptionSettings {
            range_low: 4,
            range_high: 11,
            byte_limit: 1024,
            list_limit: 5000,
        }
    }
}

impl Module for MsofficeEncryption {
    const NAME: &'static str = MsofficeEncryptionAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const READS_CARRYING_EMAIL: bool = true;
    // Four times ace3's global maximum_analysis_time. John tries a full list of an Office 2013
    // file's passwords in about 10 s on ten threads, within ace3's 60 s. One thread of Python takes
    // about 169 s. The module stops itself at 225 s and says it couldn't crack the password, as ace3
    // does when John is stopped.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(240),
        ..Resources::DEFAULT
    };
    type Output = MsofficeEncryptionAnalysis;
    type Settings = MsofficeEncryptionSettings;

    fn init(_: &MsofficeEncryptionSettings) -> Result<Self, ModuleError> {
        Ok(MsofficeEncryption)
    }
}

/// ace3's `PCodeAnalyzer` in `vbs.py`, on pcodedmp (`python/ace4_python/modules/pcodedmp.py`). Its
/// `pcodedmp_path` is gone: a worker can't start a process. `VBScriptAnalyzer` in that file doesn't
/// use pcodedmp and stays for 7.5.
pub struct PCode;

impl Module for PCode {
    const NAME: &'static str = PCodeAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    // The 30 s bin/pcodedmp_wrapper gives pcodedmp. ace3 then keeps nothing and says so in a log; here
    // the task fails, with its stack in the row.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(30),
        ..Resources::DEFAULT
    };
    type Output = PCodeAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(PCode)
    }
}

/// ace3's `XLMMacroDeobfuscatorAnalyzer` (`python/ace4_python/modules/xlmdeobfuscator.py`), on
/// XLMMacroDeobfuscator.
pub struct XlmDeobfuscator;

/// ace3's settings of the module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct XlmDeobfuscatorSettings {
    /// How long each of its two passes may take, in seconds. Two of these, and a little, must fit in
    /// the manifest's deadline, or the deadline ends the module before this does.
    pub timeout: u64,
    /// The largest file it reads, in MB.
    pub maximum_size_mb: u64,
    /// YARA rules, by name, that make it analyze a file when they match the file or anything below
    /// it. Its own rules, in `python/ace4_python/xlmdeobfuscator.yar`, do too.
    pub yara_rule_names: Vec<String>,
}

impl Default for XlmDeobfuscatorSettings {
    fn default() -> Self {
        XlmDeobfuscatorSettings {
            timeout: 30,
            maximum_size_mb: 10,
            yara_rule_names: [
                "Content_Types_Macrosheet",
                "XLM_Macrosheet_NonBin",
                "Possible_XLM_in_XLSB",
            ]
            .map(str::to_owned)
            .to_vec(),
        }
    }
}

impl Module for XlmDeobfuscator {
    const NAME: &'static str = XlmDeobfuscatorAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const RUNS_LAST: bool = true;
    // Two passes of the 30 s ace3 gives each, which the module enforces itself so a macro that spins
    // still has its cells listed, and time to load the file and write the result. ace3's global 60 s
    // would stop a second pass that started late. This deadline is for what a timer can't stop.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(75),
        ..Resources::DEFAULT
    };
    type Output = XlmDeobfuscatorAnalysis;
    type Settings = XlmDeobfuscatorSettings;

    fn init(_: &XlmDeobfuscatorSettings) -> Result<Self, ModuleError> {
        Ok(XlmDeobfuscator)
    }
}
