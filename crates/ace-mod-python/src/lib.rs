//! What the core knows about the modules the Python pool runs (PLAN.md 4.1): each one's manifest
//! and analysis type, as a Rust type. So the core's catalog, its eligibility rules and `ace schema
//! export` treat them like any other module, and the core can check their results against the
//! exported schema (4.2) with nothing from Python.
//!
//! A module's code is in `python/ace4_python/modules/`, under the manifest's name, and this crate
//! never runs. To add one: a `Module` here with its analysis type (in `ace_results::types`, as any
//! real module's is), `.module::<M>()` in `ace::python_pool`, and its file and line in
//! `python/ace4_python/registry.py`.

use std::collections::BTreeMap;
use std::time::Duration;

use ace_results::types::msoffice::MsofficeEncryptionAnalysis;
use ace_results::types::olevba::OlevbaAnalysis;
use ace_results::types::rtf::RtfOleObjectAnalysis;
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

/// ace3's `OLEVBA_Analyzer_v1_2`, on oletools (`python/ace4_python/modules/olevba_v1_2.py`).
pub struct Olevba;

/// ace3's settings of the module. Its `timeout` is gone: ace3 never read it, and the manifest's
/// deadline is what stops a task here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct OlevbaSettings {
    /// Merge a file's macros into one `macros.bas`.
    pub merge_macros: bool,
    /// The fewest of each kind in oletools' scan for a file to be tagged `olevba`. ace3 writes
    /// these as `threshold_<kind>` keys.
    pub thresholds: BTreeMap<String, u64>,
}

impl Default for OlevbaSettings {
    fn default() -> Self {
        OlevbaSettings {
            merge_macros: false,
            thresholds: BTreeMap::from([("autoexec".to_owned(), 1), ("suspicious".to_owned(), 1)]),
        }
    }
}

impl Module for Olevba {
    const NAME: &'static str = OlevbaAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    // ace3's global maximum_analysis_time, which is what stops this module there. oletools' two XLM
    // passes each stop themselves at 30 s.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        ..Resources::DEFAULT
    };
    type Output = OlevbaAnalysis;
    type Settings = OlevbaSettings;

    fn init(_: &OlevbaSettings) -> Result<Self, ModuleError> {
        Ok(Olevba)
    }
}

/// ace3's `RTFOLEObjectAnalyzer`, on oletools' rtfobj (`python/ace4_python/modules/rtfole.py`). Its
/// settings aren't ported: ace3 reads none of them but the command's path. The other two modules
/// in `rtf.py` don't use oletools, so they aren't on this pool.
pub struct RtfOle;

impl Module for RtfOle {
    const NAME: &'static str = RtfOleObjectAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    // ace3's global maximum_analysis_time. Its run_tool stops the command 5 s before that and keeps
    // an empty result; here the task fails at the deadline, with its stack in the row.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        ..Resources::DEFAULT
    };
    type Output = RtfOleObjectAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(RtfOle)
    }
}

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
