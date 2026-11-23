//! `officeparser3`: ace3's `OfficeParserAnalyzer3` (`saq/modules/file_analysis/officeparser3.py`).
//!
//! A compound file (the OLE signature, not named `.msi`, and not one file_type calls a Windows
//! installer) is run through officeparser3 into `<file>.officeparser/`, and each file its manifest
//! lists that is there and not empty is added, `extracted_from` the file, redirected to it and
//! marked `extract_urls`. A macro (`.bas`, `.frm`, `.cls`) that holds more than `Attribute VB_`
//! lines is also tagged `macro`, marked `sandbox` and typed `script.macro`. With `merge_macros` the
//! macros go into one `macros.bas` instead.
//!
//! ace3 runs officeparser3 as a process; here [`tool`] is a port of it that runs in the task, its
//! output directory held in memory. Where officeparser3 would never finish, on a FAT that goes in a
//! circle, ace3 kills it at its 90 seconds, tags the file `officeparser_failed` and marks it
//! `sandbox`, and adds what the manifest held by then, which is nothing, since Python's buffer
//! never reached the file. The port knows the loop when it comes back to a sector, and ends the
//! same way.
//!
//! Where ace-rs departs:
//!
//! - The port takes milliseconds where officeparser3 can take minutes: it finds a loop with a set
//!   where Python searches a list, and builds bytes in place where Python copies them one at a
//!   time. A file that is only slow in ace3 can pass its 90 seconds there, and here it finishes.
//!   Past 256 MiB written the port stops as if killed, and past 64 Mi FAT entries it raises
//!   `MemoryError`, where ace3's process would be killed or run out of time.
//! - A name officeparser3 would write outside its directory, through `..`, writes nothing here.
//!   ace3 writes it there, beside the document, and its manifest names it by its last part, which
//!   ace3 looks for in the directory, as here.
//! - ace3's root takes at most 500 files, the document one of them, so this adds at most 499.
//! - A name an alert path can't hold, such as `..\x`, which Linux takes as a name, isn't added.

pub mod tool;

use std::collections::BTreeMap;
use std::rc::Rc;

use ace_results::FileRole;
use ace_results::types::file_type::FileTypeAnalysis;
use ace_results::types::office::OfficeParserAnalysis;
use ace_results::{AnalysisType, NewFile, ObservableKind, ResultEnvelope};
use ace_sdk::{InputFile, Manifest, Module, ModuleError, Outcome, Parser, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{
    DIRECTIVE_EXTRACT_URLS, DIRECTIVE_SANDBOX, MAX_FILES, dir_name_fits, extracted_from, source,
};
use ace_sdk::takes::{Case, Condition, Match, Takes, Text, TypeFact};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<OfficeParserAnalyzer>();

const MACRO_EXTENSIONS: [&str; 3] = [".bas", ".frm", ".cls"];

/// ace3's settings of the module. `officeparser_path` and `timeout` are gone: no process runs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct OfficeParserSettings {
    /// Write the macros into one `macros.bas` rather than each on its own.
    pub merge_macros: bool,
}

pub struct OfficeParserAnalyzer;

/// ace3's `timeout` for officeparser3, which its reason for a killed run names. Nothing here waits
/// that long: the port stops where officeparser3 would never end.
const ACE3_TIMEOUT_SECONDS: u32 = 90;

/// `is_macro_ext`: `os.path.splitext`'s extension is one of VBA's.
pub fn is_macro_ext(name: &str) -> bool {
    let (_, ext) = ace_mod_email::naming::splitext(name.rsplit('/').next().unwrap_or(name));
    MACRO_EXTENSIONS.contains(&ext)
}

/// `is_empty_macro`: only blank lines and `Attribute VB_` lines.
pub fn is_empty_macro(data: &[u8]) -> bool {
    data.split_inclusive(|&b| b == b'\n')
        .all(|line| line.trim_ascii().is_empty() || line.starts_with(b"Attribute VB_"))
}

/// The names in the manifest, as ace3 reads it: lines decoded as UTF-8, a line that isn't skipped,
/// and each stripped.
fn manifest_names(manifest: &[u8]) -> Vec<String> {
    manifest
        .split_inclusive(|&b| b == b'\n')
        .filter_map(|line| std::str::from_utf8(line).ok())
        .map(|line| ace_pycompat::pystr::strip(line).to_owned())
        .collect()
}

/// What ace3 does with the output directory: the files to add, each with the names it stands for.
pub fn added_files(
    files: &BTreeMap<String, Rc<Vec<u8>>>,
    merge_macros: bool,
) -> Vec<(String, Rc<Vec<u8>>, Vec<String>)> {
    let Some(manifest) = files.get("manifest") else {
        return Vec::new();
    };
    let mut added: Vec<(String, Rc<Vec<u8>>, Vec<String>)> = Vec::new();
    // macros.bas, appended to, as `open(..., 'ab')` does, over any file of that name
    let mut merged: Option<Vec<u8>> = None;
    let mut merged_names = Vec::new();
    for name in manifest_names(manifest) {
        // `os.path.isfile` of the name in the directory: the names are base names
        let Some(data) = (!name.contains('/')).then(|| files.get(&name)).flatten() else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        if is_macro_ext(&name) {
            if is_empty_macro(data) {
                continue;
            }
            if merge_macros {
                merged
                    .get_or_insert_with(|| {
                        files
                            .get("macros.bas")
                            .map(|f| f.to_vec())
                            .unwrap_or_default()
                    })
                    .extend_from_slice(data);
                merged_names.push(name);
                continue;
            }
        }
        added.push((name.clone(), data.clone(), vec![name]));
    }
    if let Some(merged) = merged {
        added.push(("macros.bas".to_owned(), Rc::new(merged), merged_names));
    }
    added
}

impl Module for OfficeParserAnalyzer {
    const NAME: &'static str = OfficeParserAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const DEPENDS_ON: &'static [&'static str] = &[FileTypeAnalysis::MODULE];
    type Output = OfficeParserAnalysis;
    type Settings = OfficeParserSettings;

    fn init(_: &OfficeParserSettings) -> Result<Self, ModuleError> {
        Ok(OfficeParserAnalyzer)
    }

    fn takes(_: &OfficeParserSettings) -> Takes {
        // its checks before it runs, in its order: file_type's result, the OLE signature from the
        // file's type, and an installer by its name or file_type's description (PLAN.md decision 25)
        Takes::everything()
            .and(
                Condition::HasResult(FileTypeAnalysis::MODULE.to_owned()),
                "no file type analysis",
            )
            .and(
                Condition::type_fact(TypeFact::IsOleFile),
                "not an OLE compound document",
            )
            .and(
                Condition::Any(vec![
                    Condition::Path(Text::ends_with(".msi", Case::Lower)),
                    Condition::result_text(
                        FileTypeAnalysis::MODULE,
                        "type",
                        Text::new(Match::Contains("windows installer".to_owned()), Case::Lower),
                    ),
                ])
                .negated(),
                "a Windows installer",
            )
    }
}

/// `_add_extracted_file`: the file at `path`, written unless `written` already holds its bytes, in
/// which case it is that object again under its own name.
fn extracted_file(
    ctx: &TaskContext<OfficeParserSettings>,
    file: &InputFile,
    path: &str,
    data: &Rc<Vec<u8>>,
    written: &mut Vec<(Rc<Vec<u8>>, NewFile)>,
) -> Result<NewFile, ModuleError> {
    let macro_file = is_macro_ext(path);
    let role = macro_file.then_some(FileRole::SCRIPT_MACRO);
    let mut new_file = match written.iter().find(|(b, _)| Rc::ptr_eq(b, data)) {
        Some((_, first)) => {
            let mut again = NewFile::new(
                ace_results::AlertPath::new(path).map_err(ModuleError::other)?,
                first.sha256,
                first.size,
            );
            if let Some(role) = role {
                again.set_role(role);
            }
            again
        }
        None => {
            let new_file = ctx.write_file(path, data, role)?;
            written.push((data.clone(), new_file.clone()));
            new_file
        }
    };
    new_file.relationships.push(extracted_from(file));
    new_file.add_directive(DIRECTIVE_EXTRACT_URLS);
    new_file.redirection = Some(source(file));
    if macro_file {
        new_file.add_tag("macro");
        new_file.add_directive(DIRECTIVE_SANDBOX);
    }
    Ok(new_file)
}

impl Parser for OfficeParserAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<OfficeParserSettings>,
    ) -> Result<Outcome<OfficeParserAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let data = std::fs::read(&file.local_path)?;
        if !dir_name_fits(file, ".officeparser") {
            return Ok(Outcome::Skipped(
                "the output directory's name is too long".to_owned(),
            ));
        }
        let run = tool::run(&data);
        if let tool::End::Raised(error) = &run.end {
            tracing::info!("officeparser3 raised {error}");
        }
        if !run.manifest {
            return Ok(Outcome::Skipped(
                "officeparser3 wrote no manifest".to_owned(),
            ));
        }
        let mut result = ResultEnvelope::new(OfficeParserAnalysis::default());
        if run.end == tool::End::Killed {
            tracing::warn!("officeparser3 would not have finished");
            result.analyzed.add_tag("officeparser_failed");
            result.analyzed.add_directive(DIRECTIVE_SANDBOX);
            // what it extracted before it was stopped is still added, and the analysis is marked
            // failed, with the timeout ace3 ships (`timeout: 90`), which is what would have stopped it
            result.error = Some(format!(
                "officeparser timed out after {ACE3_TIMEOUT_SECONDS} seconds"
            ));
        }
        let mut seen: Vec<String> = Vec::new();
        // a file with the same bytes as one written, which many entries naming one chain have, is
        // the same object in the bucket under another name
        let mut written: Vec<(Rc<Vec<u8>>, NewFile)> = Vec::new();
        for (name, bytes, names) in added_files(&run.files, ctx.settings().merge_macros) {
            let path = format!("{}.officeparser/{name}", file.path);
            if ace_results::AlertPath::new(path.as_str()).is_err() {
                // a name such as `..\\x`, which Linux takes and an alert path can't hold
                tracing::info!("skipping {path:?}, which can't be a path in an alert");
                continue;
            }
            if !seen.contains(&path) {
                if seen.len() >= MAX_FILES {
                    // ace3's root takes no more files
                    continue;
                }
                ctx.check_cancelled()?;
                let new_file = extracted_file(ctx, file, &path, &bytes, &mut written)?;
                result.files.push(new_file);
                seen.push(path);
            }
            result.details.extracted_files.extend(names);
        }
        if !result.details.extracted_files.is_empty() {
            result.summary = Some(format!(
                "OfficeParser3 Analysis: extracted {} files",
                result.details.extracted_files.len()
            ));
        }
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macros_are_known_by_extension_and_emptiness() {
        assert!(is_macro_ext("Module1.bas"));
        assert!(is_macro_ext("dir/x.cls"));
        assert!(!is_macro_ext(".bas"));
        assert!(!is_macro_ext("x.BAS"));
        assert!(is_empty_macro(
            b"Attribute VB_Name = \"x\"\r\n\r\n  \nAttribute VB_X"
        ));
        assert!(!is_empty_macro(b"Attribute VB_Name = \"x\"\r\nSub A()\r\n"));
        assert!(is_empty_macro(b""));
    }

    #[test]
    fn the_manifest_is_read_as_ace3_reads_it() {
        let files = BTreeMap::from([
            (
                "manifest".to_owned(),
                b"a.txt\nempty\nmissing\nm.bas\nblank.bas\nn.cls\n\xff\ncaf\xc3\xa9\xc2\xa0\n"
                    .to_vec(),
            ),
            ("a.txt".to_owned(), b"a".to_vec()),
            ("empty".to_owned(), Vec::new()),
            ("m.bas".to_owned(), b"Sub A()\n".to_vec()),
            ("blank.bas".to_owned(), b"Attribute VB_Name = 1\n".to_vec()),
            ("n.cls".to_owned(), b"Sub B()\n".to_vec()),
            ("caf\u{e9}".to_owned(), b"c".to_vec()),
        ]);
        let files: BTreeMap<String, Rc<Vec<u8>>> =
            files.into_iter().map(|(k, v)| (k, Rc::new(v))).collect();
        let names: Vec<_> = added_files(&files, false)
            .into_iter()
            .map(|f| f.0)
            .collect();
        assert_eq!(names, ["a.txt", "m.bas", "n.cls", "caf\u{e9}"]);
        let merged = added_files(&files, true);
        assert_eq!(merged.last().unwrap().0, "macros.bas");
        assert_eq!(merged.last().unwrap().1.as_slice(), b"Sub A()\nSub B()\n");
        assert_eq!(merged.last().unwrap().2, ["m.bas", "n.cls"]);
    }
}
