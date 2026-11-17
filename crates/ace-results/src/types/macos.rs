//! The results of PLAN.md 7.5 batch 12's macOS image modules, which `ace-mod-sandbox` writes, with
//! ace3's keys: `DMGAnalysis` (`saq/modules/file_analysis/dmg.py`) and `CVE_2021_30657_Analysis`
//! (`cve.py`).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of a `dmg_analysis` result, made for a file named `*.dmg`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DmgAnalysis {
    /// What dmg2img wrote to stdout and stderr. None when it was stopped.
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    /// The raw image dmg2img wrote, by its path in the alert: the file's with `.img` for `.dmg`.
    /// None when it wrote none.
    pub image_file: Option<String>,
    /// The files of `7z l`'s listing of the image, each line as 7z prints it, without the folders.
    /// When dmg2img or 7z failed or didn't finish, the result's `error` says so.
    pub file_list: Vec<String>,
}

impl AnalysisType for DmgAnalysis {
    const NAME: &'static str = "dmg_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "dmg_analyzer";
}

/// The details of a `cve_2021_30657_analysis` result, made for an image dmg_analyzer wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Cve202130657Analysis {
    /// Each script found in an app bundle's `Contents/MacOS/`, by the path it was added under, its
    /// name, with libmagic's mime type for it.
    /// When the members weren't all checked the result's `error` says why: 7z failed or the
    /// runner stopped it, or a member couldn't be named to it.
    pub suspect_files: BTreeMap<String, String>,
}

impl AnalysisType for Cve202130657Analysis {
    const NAME: &'static str = "cve_2021_30657_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "cve_2021_30657_analyzer";
}
