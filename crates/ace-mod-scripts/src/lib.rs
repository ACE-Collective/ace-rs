//! ace3's RTF and script modules (PLAN.md 7.5 batch 6): `microsoft_script_encoding_analysis`,
//! `extracted_rtf_analyzer`, `vbscript_analyzer` and `nowhitespace_analyzer`. Checks and
//! transforms of single files, with ace3's names, tags, detections and `yara_meta` types.
//!
//! `microsoft_script_encoding_analysis` decodes a script with the tables of the Perl decoder ace3
//! runs (`bin/jscript.decode.pl`), ported in [`mse::decode`], which matches it byte for byte
//! (`docs/measurements/scripts.md`). The other three read bytes, names and earlier results; none
//! parses RTF: `extracted_rtf_analyzer` reads which modules added its file, and
//! `nowhitespace_analyzer` checks an RTF's first bytes as file_type does.

pub mod mse;
pub mod rtf;
pub mod vbs;

use std::time::Duration;

pub use mse::MicrosoftScriptEncodingAnalyzer;
pub use rtf::{ExtractedRtfAnalyzer, NoWhiteSpaceAnalyzer};
pub use vbs::VbScriptAnalyzer;

use ace_results::{ObservableKind, ObservableRef};
use ace_sdk::{InputFile, Resources};

/// ace3's global `maximum_analysis_time`, which is what stops these modules there. Each reads its
/// file once, in time and memory linear in its size (`docs/measurements/scripts.md`).
const RESOURCES: Resources = Resources {
    timeout: Duration::from_secs(60),
    memory_mb: 1024,
    cpu_seconds: 60,
};

const DIRECTIVE_SANDBOX: &str = "sandbox";
/// ace3's `NAME_MAX_BYTES`: a longer name fails to open, as on ace3's file system.
const NAME_MAX_BYTES: usize = 255;

/// The input file as an observable, for a redirection.
fn source(file: &InputFile) -> ObservableRef {
    ObservableRef::new(ObservableKind::File, file.sha256.to_hex())
}

/// Whether a file `<file><suffix>` beside the file can be opened: `open` fails on a name past
/// `NAME_MAX`, which ace3 logs as the module's exception, keeping what the analysis had by then.
fn name_fits(file: &InputFile, suffix: &str) -> bool {
    file.name().len() + suffix.len() <= NAME_MAX_BYTES
}

/// What ace3's engine marks the analysis with when `open` of `<file><suffix>` raises out of its
/// module on such a name: the exception as `<type>: <message>`. ace3's goes on with its crash
/// report's id, and names the file by its path on its node, where this is its path in the alert.
fn name_too_long(file: &InputFile, suffix: &str) -> String {
    format!(
        "OSError: [Errno 36] File name too long: '{}{suffix}'",
        file.path
    )
}

/// `path.lower().endswith(suffix)` for an ASCII suffix. No character outside ASCII lowers to one
/// in ASCII but the Kelvin sign, to `k`, which none of these suffixes has.
fn ends_with_lower(path: &str, suffix: &str) -> bool {
    path.len() >= suffix.len()
        && path.is_char_boundary(path.len() - suffix.len())
        && path[path.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_suffix_is_matched_whatever_its_case() {
        assert!(ends_with_lower("a/LOUD.VBE", ".vbe"));
        assert!(ends_with_lower("x.vbs", ".vbs"));
        assert!(!ends_with_lower("x.vbs.txt", ".vbs"));
        assert!(!ends_with_lower("é", ".vbs"));
        assert!(!ends_with_lower("aé.vbs", ".vbe"));
    }
}
