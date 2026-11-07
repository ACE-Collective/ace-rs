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

use ace_results::types::olevba::OlevbaAnalysis;
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
