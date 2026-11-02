//! `archive_analysis`: the files an archive module took out of an archive (ace3's
//! `ArchiveAnalysis`, `saq/modules/file_analysis/archive.py`).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of an `archive_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveAnalysis {
    /// How many entries the archive lists. Like ace3, this counts directories for JAR, Excel and
    /// RAR archives and only files for the others.
    pub file_count: u64,
    /// The paths of the files extracted, inside the archive's `.extracted` directory, in the
    /// order they were added: the riskiest kinds of file first.
    pub extracted_files: Vec<String>,
}

impl AnalysisType for ArchiveAnalysis {
    const NAME: &'static str = "archive_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "archive";
}
