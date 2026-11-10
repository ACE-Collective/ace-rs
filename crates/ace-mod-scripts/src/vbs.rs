//! `vbscript_analyzer`: ace3's `VBScriptAnalyzer` (`saq/modules/file_analysis/vbs.py`).
//!
//! A file whose name ends `.vbs` is read a line at a time, skipping lines that start, after
//! whitespace, with `'` or `REM`. Whitespace, by Python's `str.isspace` of each byte, is passed over;
//! any other byte that isn't a hex digit ends a run of hex digits, and runs of 5 or more count. A
//! run goes on across lines and across the comment lines skipped, as ace3's does. A file with a run
//! gets a result; many long runs of one length, or hex digits making up enough of the file, are
//! detections, and a run longer than `large_hex_string_size` tags the file `large_hex_string`.
//!
//! ace3's check for many runs of one length compares the length with `large_hex_string_quantity`
//! where its comment says `large_hex_string_size`; both are 50 by default, and the port keeps
//! ace3's comparison.

use std::collections::BTreeMap;
use std::fs;

use ace_pycompat::json::float_repr;
use ace_results::types::scripts::VbScriptAnalysis;
use ace_results::{AnalysisType, Detection, ObservableKind, ResultEnvelope};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{DIRECTIVE_SANDBOX, ends_with_lower};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<VbScriptAnalyzer>();

/// ace3's built-in `VBS_HEX_ENCODED_CONTENT` signature.
const VBS_HEX_ENCODED_CONTENT: &str = "e46a6485-7ccd-4cba-8196-7540c5e7a1b9";
const DISPLAY_NAME: &str = "VBScript Analysis";
/// ace3 ignores shorter runs.
const MIN_RUN: u64 = 5;

/// ace3's settings of the module.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct VbScriptSettings {
    /// A run longer than this tags the file `large_hex_string`.
    pub large_hex_string_size: u64,
    /// Runs of one length longer than this, more than `large_hex_string_quantity_count` of them,
    /// are a detection.
    pub large_hex_string_quantity: u64,
    /// How many runs of one length that takes.
    pub large_hex_string_quantity_count: u64,
    /// The share of the file in hex digits, from 0.0 to 0.99, that is a detection.
    pub hex_string_percentage_limit: f64,
}

impl Default for VbScriptSettings {
    fn default() -> Self {
        VbScriptSettings {
            large_hex_string_size: 50,
            large_hex_string_quantity: 50,
            large_hex_string_quantity_count: 100,
            hex_string_percentage_limit: 0.15,
        }
    }
}

pub struct VbScriptAnalyzer;

impl Module for VbScriptAnalyzer {
    const NAME: &'static str = VbScriptAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const RESOURCES: Resources = crate::RESOURCES;
    type Output = VbScriptAnalysis;
    type Settings = VbScriptSettings;

    fn init(_: &VbScriptSettings) -> Result<Self, ModuleError> {
        Ok(VbScriptAnalyzer)
    }
}

/// `chr(c).isspace()` for a byte.
fn is_space(byte: u8) -> bool {
    matches!(byte, 0x09..=0x0D | 0x1C..=0x20 | 0x85 | 0xA0)
}

/// `bytes.lstrip()`, which strips ASCII whitespace only.
fn lstrip(line: &[u8]) -> &[u8] {
    let start = line
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C))
        .unwrap_or(line.len());
    &line[start..]
}

/// The runs of hex digits the module counts, in order, and how many hex digits those lines hold.
pub fn hex_runs(data: &[u8]) -> (Vec<u64>, u64) {
    let mut lengths = Vec::new();
    let mut run = 0u64;
    let mut total = 0u64;
    // `mm.readline`: each line with its `\n`
    for line in data.split_inclusive(|b| *b == b'\n') {
        let stripped = lstrip(line);
        if stripped.starts_with(b"'") || stripped.starts_with(b"REM") {
            continue;
        }
        for &byte in line {
            if is_space(byte) {
                continue;
            }
            if byte.is_ascii_hexdigit() {
                run += 1;
                total += 1;
            } else {
                if run >= MIN_RUN {
                    lengths.push(run);
                }
                run = 0;
            }
        }
    }
    if run >= MIN_RUN {
        lengths.push(run);
    }
    (lengths, total)
}

/// What the module finds in `data`, a file of `data.len()` bytes, or `None` with no run.
pub fn analyze_bytes(
    settings: &VbScriptSettings,
    data: &[u8],
) -> Option<ResultEnvelope<VbScriptAnalysis>> {
    let (lengths, total) = hex_runs(data);
    let largest = lengths.iter().copied().max()?;
    // Python's int / int, then * 100.0: each step rounds once, as here
    let share = total as f64 / data.len() as f64;
    let percentage = share * 100.0;
    let mut result = ResultEnvelope::new(VbScriptAnalysis {
        total_hex_strings: lengths.len() as u64,
        largest_hex_string: largest,
        percentage_of_hex_strings: percentage,
    });
    result.summary = Some(format!(
        "{DISPLAY_NAME}: {} total hex strings, {largest} largest hex string, {}% percentage of file is hex strings",
        lengths.len(),
        float_repr(percentage)
    ));

    let mut distribution: BTreeMap<u64, u64> = BTreeMap::new();
    for length in &lengths {
        *distribution.entry(*length).or_default() += 1;
    }
    let analyzed = &mut result.analyzed;
    if distribution.iter().any(|(length, count)| {
        *length > settings.large_hex_string_quantity
            && *count > settings.large_hex_string_quantity_count
    }) {
        analyzed.detections.push(
            Detection::new("large number of large hex strings of same length")
                .with_signature(VBS_HEX_ENCODED_CONTENT),
        );
        analyzed.add_directive(DIRECTIVE_SANDBOX);
    }
    if share >= settings.hex_string_percentage_limit {
        analyzed.detections.push(
            Detection::new(format!(
                "a large percentage of the file is ascii hex ({percentage:.2}%)"
            ))
            .with_signature(VBS_HEX_ENCODED_CONTENT),
        );
        analyzed.add_directive(DIRECTIVE_SANDBOX);
    }
    if largest > settings.large_hex_string_size {
        analyzed.add_tag("large_hex_string");
        analyzed.add_directive(DIRECTIVE_SANDBOX);
    }
    Some(result)
}

impl Parser for VbScriptAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<VbScriptSettings>,
    ) -> Result<Outcome<VbScriptAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        if file.size == 0 {
            return Ok(Outcome::Skipped("an empty file".to_owned()));
        }
        if !ends_with_lower(file.path.as_str(), ".vbs") {
            return Ok(Outcome::Skipped("not a .vbs file".to_owned()));
        }
        let data = fs::read(&file.local_path)?;
        Ok(match analyze_bytes(ctx.settings(), &data) {
            Some(result) => Outcome::Done(result),
            None => Outcome::Skipped("no hex strings".to_owned()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_go_on_over_whitespace_and_skipped_comment_lines() {
        assert_eq!(hex_runs(b"abc\n  ' x\nde 12\n"), (vec![7], 7));
        assert_eq!(hex_runs(b"abcd-1234"), (vec![], 8));
        // rem in lower case isn't a comment, and \x85 and \xa0 are spaces to str.isspace
        assert_eq!(hex_runs(b"rem abcde\n\x85\xa0f"), (vec![6], 7));
        assert_eq!(hex_runs(b"\tREM abcdef\nx"), (vec![], 0));
    }

    #[test]
    fn a_tie_rounds_to_even_as_python_s_format_does() {
        let mut data = b"0123456789".repeat(5);
        data.push(b'\n');
        data.extend(std::iter::repeat_n(b'-', 269));
        let result = analyze_bytes(&VbScriptSettings::default(), &data).expect("a result");
        assert_eq!(result.details.percentage_of_hex_strings, 15.625);
        assert_eq!(
            result.analyzed.detections[0].description,
            "a large percentage of the file is ascii hex (15.62%)"
        );
        assert_eq!(
            result.summary.as_deref(),
            Some(
                "VBScript Analysis: 1 total hex strings, 50 largest hex string, 15.625% percentage of file is hex strings"
            )
        );
    }

    #[test]
    fn many_long_runs_of_one_length_are_a_detection() {
        let settings = VbScriptSettings::default();
        let lines = |_: usize| "\"".to_owned() + &"a".repeat(51) + "\"\n";
        let many: String = (0..101).map(lines).collect();
        let result = analyze_bytes(&settings, many.as_bytes()).expect("a result");
        assert_eq!(
            result.analyzed.detections[0].description,
            "large number of large hex strings of same length"
        );
        let hundred: String = (0..100).map(lines).collect();
        let result = analyze_bytes(&settings, hundred.as_bytes()).expect("a result");
        assert!(
            result
                .analyzed
                .detections
                .iter()
                .all(|d| d.description != "large number of large hex strings of same length")
        );
    }
}
