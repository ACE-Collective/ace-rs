//! `command_line_analyzer`: ace3's `CommandLineAnalyzer` (`saq/modules/command_line.py`).
//!
//! A command line's Windows paths become `file_path` observables, and `file_location` observables
//! too when the command line `executed_on` a host, with `collect_file` when it has it. Its base64
//! runs that decode to at least `base64_minimum_length` bytes, or any length right after
//! PowerShell's `-EncodedCommand` (or a prefix of it, or `-ec`), are written to files tagged
//! `base64` with `yara_meta` type `payload.base64`.
//!
//! Where ace-rs departs:
//!
//! - The details name each payload's file by its path in the alert, where ace3 names its path on
//!   its node.
//! - ace3 writes every payload to a file and its root takes at most 500 file observables
//!   (`maximum_observable_count`); here the first 500 payloads are written, as ace-rs's core has no
//!   such limit, and the rest are in the details with the name their file would have had.
//! - ace3's `create_output_file` numbers a name already taken in the alert's files, `_000` and on;
//!   here only the names this result takes are known, so a second command line in the alert writes
//!   `command_line_base64_payload.bin` again, with other bytes.

use std::collections::{BTreeSet, HashSet};

use ace_results::FileRole;
use ace_results::types::values::{Base64Payload, CommandLineAnalysis};
use ace_results::{AnalysisType, ObservableKind, RelationshipKind, ResultEnvelope};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::py::{
    decode_base64, find_nt_paths_in_text, is_base64, is_nt_path, ntpath_basename,
    shlex_split_nonposix,
};
use ace_sdk::observable_rules as observable;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<CommandLineAnalyzer>();

const PAYLOAD_NAME: &str = "command_line_base64_payload.bin";
/// ace3's `maximum_observable_count` for `file`: a root holds at most 500 file observables, so ace3
/// writes every payload but adds no more than this. ace-rs's core has no such limit, so this module
/// writes the first 500 payloads' files, and a crafted command line of thousands of short encoded
/// words can't make a task upload thousands of files (docs/measurements/observable-values.md).
const MAX_PAYLOAD_FILES: usize = 500;
const DIRECTIVE_COLLECT_FILE: &str = "collect_file";
/// Program names whose `-e` abbreviates `-EncodedCommand`.
const POWERSHELL_PROGRAMS: [&str; 4] = ["powershell", "powershell.exe", "pwsh", "pwsh.exe"];
/// PowerShell reads the en dash, em dash and horizontal bar as a dash.
const DASHES: [char; 4] = ['-', '\u{2013}', '\u{2014}', '\u{2015}'];

/// ace3's `analysis_module_command_line_analyzer` settings.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct CommandLineSettings {
    /// The fewest decoded bytes a base64 run needs to be a payload, except right after
    /// PowerShell's `-EncodedCommand`.
    pub base64_minimum_length: usize,
}

impl Default for CommandLineSettings {
    fn default() -> Self {
        CommandLineSettings {
            base64_minimum_length: 128,
        }
    }
}

pub struct CommandLineAnalyzer;

impl Module for CommandLineAnalyzer {
    const NAME: &'static str = CommandLineAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::CommandLine];
    type Output = CommandLineAnalysis;
    type Settings = CommandLineSettings;

    fn init(_: &CommandLineSettings) -> Result<Self, ModuleError> {
        Ok(CommandLineAnalyzer)
    }
}

/// `RE_BASE64_RUN.findall`: each maximal run of either alphabet's characters, with at most two
/// `=` after it.
fn base64_runs(value: &str) -> Vec<&str> {
    let is_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '_' | '-');
    let mut runs = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.find(is_char) {
        let after = &rest[start..];
        let mut end = after.find(|c: char| !is_char(c)).unwrap_or(after.len());
        for _ in 0..2 {
            if after[end..].starts_with('=') {
                end += 1;
            }
        }
        runs.push(&after[..end]);
        rest = &after[end..];
    }
    runs
}

/// `_remove_prefix_substrings`: drops a path another one starts with, a word shlex cut short. ace3
/// compares every pair; here the paths are sorted, where those that start with a path come right
/// after it, so a crafted command line of many paths costs `n log n`.
fn remove_prefix_substrings(paths: &[String]) -> Vec<String> {
    let sorted: BTreeSet<&str> = paths.iter().map(String::as_str).collect();
    let cut: HashSet<&str> = sorted
        .iter()
        .zip(sorted.iter().skip(1))
        .filter(|(path, next)| next.starts_with(**path))
        .map(|(path, _)| *path)
        .collect();
    paths
        .iter()
        .filter(|path| !cut.contains(path.as_str()))
        .cloned()
        .collect()
}

/// The result being built.
struct Output<'a> {
    ctx: &'a TaskContext<CommandLineSettings>,
    result: ResultEnvelope<CommandLineAnalysis>,
    payload_names: usize,
    /// The observables added, as ace3's root holds one of each.
    added: HashSet<(String, String)>,
}

impl Output<'_> {
    /// `_add_base64_payload`.
    fn add_payload(&mut self, encoded: &str, decoded: &[u8]) -> Result<(), ModuleError> {
        // create_output_file's name, then <name>_NNN<ext> for each one after
        let path = match self.payload_names {
            0 => PAYLOAD_NAME.to_owned(),
            n => format!("command_line_base64_payload_{:03}.bin", n - 1),
        };
        self.payload_names += 1;
        if self.result.files.len() < MAX_PAYLOAD_FILES {
            let mut file = self
                .ctx
                .write_file(&path, decoded, FileRole::PAYLOAD_BASE64)
                .map_err(|e| ModuleError::other(e.to_string()))?;
            file.tags.push("base64".to_owned());
            self.result.files.push(file);
        }
        self.result.details.base64_payloads.push(Base64Payload {
            base64: encoded.to_owned(),
            file_path: path,
        });
        Ok(())
    }

    /// An observable, unless the result has it.
    fn add(&mut self, o: ace_results::NewObservable) {
        if self.added.insert((o.kind.to_string(), o.value.clone())) {
            self.result.observables.push(o);
        }
    }

    /// `_add_file_path`.
    fn add_file_path(&mut self, path: &str) {
        if let Some(o) = observable::new(ObservableKind::FilePath, path) {
            self.add(o);
        }
        self.result.details.file_paths.push(path.to_owned());
        let command_line = self.ctx.observable();
        if let Some(host) = command_line.relationship(RelationshipKind::ExecutedOn) {
            // create_file_location: the host stripped, then @, then the path
            let location = format!("{}@{path}", ace_pycompat::pystr::strip(&host.target.value));
            if let Some(mut o) = observable::new(ObservableKind::FileLocation, &location) {
                if command_line.has_directive(DIRECTIVE_COLLECT_FILE) {
                    o.directives.push(DIRECTIVE_COLLECT_FILE.to_owned());
                }
                self.add(o);
            }
        }
    }
}

/// `generate_summary`, with ace3's two spaces after "extracted".
fn summary(details: &CommandLineAnalysis) -> Option<String> {
    let mut parts = Vec::new();
    if !details.file_paths.is_empty() {
        parts.push(format!("{} file paths", details.file_paths.len()));
    }
    if !details.base64_payloads.is_empty() {
        parts.push(format!("{} base64 payloads", details.base64_payloads.len()));
    }
    (!parts.is_empty()).then(|| format!("Command Line Analysis: extracted  {}", parts.join(", ")))
}

impl Parser for CommandLineAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<CommandLineSettings>,
    ) -> Result<Outcome<CommandLineAnalysis>, ModuleError> {
        let value = ctx.observable().value.as_str();
        let minimum = ctx.settings().base64_minimum_length;
        let mut out = Output {
            ctx,
            result: ResultEnvelope::new(CommandLineAnalysis::default()),
            payload_names: 0,
            added: HashSet::new(),
        };
        let mut candidate_paths: Vec<String> = Vec::new();

        let mut ignore_size_restriction = false;
        let mut runs_powershell = false;
        // an unbalanced quote skips only the word pass
        let tokens = shlex_split_nonposix(value).unwrap_or_default();
        for token in &tokens {
            let mut token = token.as_str();
            while token.starts_with('"') && token.ends_with('"') {
                // a lone quote is "" after this, as token[1:-1]
                token = token.get(1..token.len().saturating_sub(1)).unwrap_or("");
            }
            if POWERSHELL_PROGRAMS
                .contains(&ace_pycompat::pystr::lower(&ntpath_basename(token)).as_ref())
            {
                runs_powershell = true;
            }
            if token.starts_with(DASHES) || token.starts_with('/') {
                let mut flag_name: &str = &token[token.chars().next().map_or(0, char::len_utf8)..];
                if flag_name.starts_with(DASHES) {
                    flag_name = &flag_name[flag_name.chars().next().map_or(0, char::len_utf8)..];
                }
                let flag_name = ace_pycompat::pystr::lower(flag_name);
                if runs_powershell
                    && (flag_name == "ec"
                        || (!flag_name.is_empty()
                            && "encodedcommand".starts_with(flag_name.as_ref())))
                {
                    ignore_size_restriction = true;
                }
                continue;
            }
            if is_nt_path(token) {
                candidate_paths.push(token.to_owned());
            }
            if is_base64(token) {
                // a word made of base64 characters that doesn't decode is no payload, and ace3 goes
                // on to the next word without resetting the flag
                let Ok(decoded) = decode_base64(token) else {
                    continue;
                };
                if ignore_size_restriction || decoded.len() >= minimum {
                    out.add_payload(token, &decoded)?;
                }
            }
            ignore_size_restriction = false;
        }

        // base64 that is only part of a word
        let mut extracted: HashSet<String> = out
            .result
            .details
            .base64_payloads
            .iter()
            .map(|p| p.base64.clone())
            .collect();
        for candidate in base64_runs(value) {
            if extracted.contains(candidate) || candidate.len() * 3 / 4 < minimum {
                continue;
            }
            let Ok(decoded) = decode_base64(candidate) else {
                continue;
            };
            if decoded.len() >= minimum {
                out.add_payload(candidate, &decoded)?;
                extracted.insert(candidate.to_owned());
            }
        }

        // paths shlex missed, such as those in a quoted script body
        let seen: HashSet<String> = candidate_paths.iter().cloned().collect();
        for path in find_nt_paths_in_text(value) {
            if !seen.contains(&path) {
                candidate_paths.push(path);
            }
        }
        for path in remove_prefix_substrings(&candidate_paths) {
            out.add_file_path(&path);
        }

        let mut result = out.result;
        result.summary = summary(&result.details);
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_are_findalls() {
        assert_eq!(base64_runs("a=== b-c/d=x"), ["a==", "b-c/d=", "x"]);
        assert_eq!(base64_runs("  "), Vec::<&str>::new());
    }

    #[test]
    fn prefixes_go() {
        let paths = [
            "C:\\Program".to_owned(),
            "C:\\Program Files\\a.exe".to_owned(),
        ];
        assert_eq!(
            remove_prefix_substrings(&paths),
            ["C:\\Program Files\\a.exe"]
        );
    }
}
