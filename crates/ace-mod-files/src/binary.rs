//! `binary_file_analyzer`: ace3's `BinaryFileAnalyzer` (`saq/modules/file_analysis/binary.py`).
//!
//! For an RTF file, or an EPS file with `.doc` in its path, a NUL byte anywhere but the last
//! byte tags the file `unexpected_binary_data` and sandboxes it. Every such file gets an empty
//! result. ace3 looks for `.doc` in the file's path on its node, whose directories are its own;
//! here it's the alert path.

use std::fs::File;
use std::io::Read;

use ace_results::types::binary::BinaryFileAnalysis;
use ace_results::{AnalysisType, ObservableKind, ResultEnvelope};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<BinaryFileAnalyzer>();

const DIRECTIVE_SANDBOX: &str = "sandbox";

pub struct BinaryFileAnalyzer;

impl Module for BinaryFileAnalyzer {
    const NAME: &'static str = BinaryFileAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    type Output = BinaryFileAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(BinaryFileAnalyzer)
    }
}

/// `is_supported_file`: `{\rt` (stricter than file_type's check), or an EPS header in a file
/// whose path holds `.doc`.
pub fn is_supported(path: &str, head: &[u8]) -> bool {
    let eps = head.starts_with(b"\xc5\xd0\xd3\xc6") || head.starts_with(b"%!PS-Adobe-");
    head.starts_with(b"{\\rt") || (eps && path.contains(".doc"))
}

/// A NUL anywhere but the file's last byte.
pub fn has_unexpected_nul(data: &[u8]) -> bool {
    let body = data.split_last().map_or(data, |(_, rest)| rest);
    body.contains(&0)
}

impl Parser for BinaryFileAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<BinaryFileAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        if file.size == 0 {
            return Ok(Outcome::Skipped("an empty file".to_owned()));
        }
        let mut head = Vec::with_capacity(11);
        File::open(&file.local_path)?
            .take(11)
            .read_to_end(&mut head)?;
        if !is_supported(file.path.as_str(), &head) {
            return Ok(Outcome::Skipped("not an RTF or EPS file".to_owned()));
        }
        let data = std::fs::read(&file.local_path)?;
        let mut result = ResultEnvelope::new(BinaryFileAnalysis {});
        if has_unexpected_nul(&data) {
            result.analyzed.add_tag("unexpected_binary_data");
            result.analyzed.add_directive(DIRECTIVE_SANDBOX);
        }
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtf_and_eps_with_a_nul_before_the_end() {
        assert!(is_supported("a.rtf", b"{\\rtf1"));
        assert!(!is_supported("a.rtf", b"\\rtf1"));
        assert!(is_supported("a.doc.extracted/x.eps", b"%!PS-Adobe-3.0"));
        assert!(!is_supported("x.eps", b"%!PS-Adobe-3.0"));
        assert!(has_unexpected_nul(b"{\\rt\0x"));
        assert!(!has_unexpected_nul(b"{\\rtx\0"));
        assert!(!has_unexpected_nul(b""));
    }
}
