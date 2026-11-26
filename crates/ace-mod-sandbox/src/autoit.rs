//! ace3's `AutoItAnalyzer` (`saq/modules/file_analysis/autoit.py`): unautoit lists and extracts the
//! resources of a compiled AutoIt script, and its decompiled `.au3` scripts become files. ace3 runs
//! unautoit as a plain process (`run_tool`); here it runs in the sandbox runner.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use ace_mod_files::checks::is_pe_file;
use ace_results::FileRole;
use ace_results::types::executables::AutoItAnalysis;
use ace_results::{ObservableKind, Relationship, RelationshipKind, ResultEnvelope};
use ace_sdk::takes::{Case, Condition, Takes, Text, TypeFact};
use ace_sdk::tools::{ToolOutput, ToolRun, ToolStop};
use ace_sdk::{Module, ModuleError, Outcome, Parser, Resources, TaskContext};

use crate::{MAX_FILES, head, item_list, name_fits, source};

/// The autoit module.
pub struct AutoItAnalyzer;

impl Module for AutoItAnalyzer {
    const NAME: &'static str = "autoit";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const TOOLS: &'static [&'static str] = &["unautoit"];
    /// ace3's `maximum_analysis_time`, 60 s, which each run's timeout comes from: ace3's module
    /// gives unautoit none of its own.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        memory_mb: 512,
        cpu_seconds: 60,
    };
    type Output = AutoItAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(AutoItAnalyzer)
    }

    fn takes(_: &()) -> Takes {
        // is_autoit's first test, from the file's type (PLAN.md decision 25), so the core queues
        // it for a PE file or an .au3 and no other: about 20 tasks over the sample set where it was
        // 4,072 (docs/measurements/module-timings.md). The marker can be anywhere in the file, so
        // reading for it stays in analyze.
        Takes::everything()
            .and(Condition::not_empty(), "an empty file")
            .and(
                Condition::Any(vec![
                    Condition::type_fact(TypeFact::IsPeFile),
                    Condition::Name(Text::ends_with(".au3", Case::Lower)),
                ]),
                "neither a PE file nor named .au3",
            )
    }
}

/// `is_file_type.AUTOIT_SCAN_CHUNK_SIZE`: the file is read this much at a time.
const CHUNK: usize = 8 * 1024 * 1024;

/// Whether `data` holds `AU3!EA05` or `AU3!EA06`, ace3's `RE_AUTOIT_MAGIC`.
fn has_marker(data: &[u8]) -> bool {
    data.windows(8)
        .any(|w| w.starts_with(b"AU3!EA0") && (w[7] == b'5' || w[7] == b'6'))
}

/// `is_autoit`: a PE file, or a name ending `.au3`, holding the marker. The file is read in
/// chunks, the end of each carried into the next, so a marker across a boundary is found and the
/// memory stays one chunk's whatever the file's size.
pub fn is_autoit(path: &str, local: &Path) -> std::io::Result<bool> {
    if !is_pe_file(&head(local, 2)?) && !path.to_lowercase().ends_with(".au3") {
        return Ok(false);
    }
    let mut file = File::open(local)?;
    let mut buffer = vec![0u8; CHUNK + 7];
    let mut carried = 0;
    loop {
        let mut read = 0;
        while read < CHUNK {
            let n = file.read(&mut buffer[carried + read..carried + CHUNK])?;
            if n == 0 {
                break;
            }
            read += n;
        }
        if read == 0 {
            return Ok(false);
        }
        let end = carried + read;
        if has_marker(&buffer[..end]) {
            return Ok(true);
        }
        let keep = 7.min(end);
        buffer.copy_within(end - keep..end, 0);
        carried = keep;
    }
}

/// What ace3 records for a run its `run_tool` stopped, `unautoit <what> timed out`, and here why
/// the runner stopped one for its other limits.
fn stopped_text(what: &str, output: &ToolOutput) -> Option<String> {
    match output.stopped()? {
        ToolStop::Timeout => Some(format!("unautoit {what} timed out")),
        stop => Some(format!("unautoit {what} was stopped: {}", stop.describe())),
    }
}

impl Parser for AutoItAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<AutoItAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        if file.size == 0 || !is_autoit(file.path.as_str(), &file.local_path)? {
            return Ok(Outcome::Skipped("not a compiled AutoIt script".to_owned()));
        }
        let mut result = ResultEnvelope::new(AutoItAnalysis::default());
        result.analyzed.add_tag("autoit");
        let output_dir = format!("{}.autoit", file.path);
        result.details.output_dir = Some(output_dir.clone());
        let local = file.local_path.display().to_string();

        let list = ToolRun::new("unautoit", ["list", local.as_str()])
            .read(&file.local_path)
            .timeout(ctx.time_left());
        let output = ctx.run_tool(list)?;
        if let Some(error) = stopped_text("list", &output) {
            result.summary = summary(&result.details, Some(&error));
            result.error = Some(error);
            return Ok(Outcome::Done(result));
        }
        // ace3 keeps run_tool's bytes, which its JSON encoder writes as unicode_escape decodes them
        result.details.stdout = Some(as_ace3_writes_bytes(&output.stdout));
        result.details.stderr = Some(as_ace3_writes_bytes(&output.stderr));

        let extract = ToolRun::new(
            "unautoit",
            ["extract-all", "--output-dir", "out", local.as_str()],
        )
        .read(&file.local_path)
        .keep_tree()
        .timeout(ctx.time_left());
        let output = ctx.run_tool(extract)?;
        if let Some(error) = stopped_text("extract-all", &output) {
            // what it extracted before it was stopped may be cut short
            result.summary = summary(&result.details, Some(&error));
            result.error = Some(error);
            return Ok(Outcome::Done(result));
        }
        // the decompiled scripts at the top of the output directory, as ace3's os.listdir sees them
        for (name, path) in &output.outputs {
            let Some(script) = name.strip_prefix("out/") else {
                continue;
            };
            if script.contains('/') || !script.ends_with(".au3") {
                continue;
            }
            result.details.scripts.push(script.to_owned());
            let target = format!("{output_dir}/{script}");
            if result.files.len() >= MAX_FILES || !name_fits(&target) {
                continue;
            }
            let mut new_file =
                ctx.write_file_from(&target, &mut File::open(path)?, FileRole::SCRIPT_AUTOIT)?;
            new_file.relationships.push(Relationship::new(
                RelationshipKind::ExtractedFrom,
                source(file),
            ));
            new_file.tags.push("autoit".to_owned());
            // avoid recursion, ace3 says
            new_file.exclude_modules.push("autoit".to_owned());
            result.files.push(new_file);
        }
        result.summary = summary(&result.details, None);
        Ok(Outcome::Done(result))
    }
}

/// Bytes in a result's details, as ace3's JSON encoder writes them: `bytes.decode('unicode_escape',
/// 'replace')`, so a Windows path's `\U` becomes U+FFFD and its `\a` a bell. A surrogate, which a
/// Rust string can't hold, is U+FFFD too.
fn as_ace3_writes_bytes(bytes: &[u8]) -> String {
    ace_pycompat::escape::decode_unicode_escape(bytes)
        .into_iter()
        .map(|c| char::from_u32(c).unwrap_or('\u{fffd}'))
        .collect()
}

/// `AutoItAnalysis.generate_summary`, with the result's error.
fn summary(details: &AutoItAnalysis, error: Option<&String>) -> Option<String> {
    if let Some(error) = error.filter(|e| !e.is_empty()) {
        return Some(format!("AutoIt Analysis: {error}"));
    }
    if details.scripts.is_empty() {
        return None;
    }
    Some(format!(
        "AutoIt Analysis: decompiled {}",
        item_list(&details.scripts)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether the declaration takes a file of this path, size and type (None: its type step failed).
    fn takes(path: &str, size: u64, pe: Option<bool>) -> bool {
        let type_facts = pe.map(|is_pe_file| ace_results::types::file_type::TypeFacts {
            is_pe_file,
            ..Default::default()
        });
        let results = std::collections::BTreeMap::new();
        let facts = ace_sdk::takes::Facts {
            kind: ObservableKind::File,
            directives: &[],
            directive_sources: &[],
            relationships: &[],
            redirected: false,
            added_by: &[],
            at_root: false,
            mode: None,
            file: Some(ace_sdk::takes::FileFacts {
                path,
                size: Some(size),
                facts: type_facts.as_ref(),
                role: None,
                yara_meta: Some(&[]),
            }),
            results: &results,
            origins: None,
        };
        AutoItAnalyzer::takes(&()).check(&facts).is_ok()
    }

    #[test]
    fn it_takes_a_pe_file_or_an_au3_and_nothing_else() {
        assert!(takes("dropper.bin", 10, Some(true)));
        assert!(takes("dir/x.au3", 10, Some(false)));
        assert!(takes("dir/X.AU3", 10, Some(false)));
        assert!(!takes("dir/x.txt", 10, Some(false)));
        assert!(!takes("dir/x.au3.txt", 10, Some(false)));
        // as is_autoit, an empty file never is one
        assert!(!takes("x.exe", 0, Some(true)));
        // a file whose type step failed isn't declined by its type
        assert!(takes("x.bin", 10, None));
    }

    #[test]
    fn the_marker_is_found_across_a_chunk_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.exe");
        let mut data = b"MZ".to_vec();
        data.resize(CHUNK - 3, 0);
        data.extend_from_slice(b"AU3!EA06");
        data.resize(CHUNK + 100, 0);
        std::fs::write(&path, &data).unwrap();
        assert!(is_autoit("x.exe", &path).unwrap());
        data[CHUNK - 3..CHUNK + 5].copy_from_slice(b"AU3!EA07");
        std::fs::write(&path, &data).unwrap();
        assert!(!is_autoit("x.exe", &path).unwrap());
        // a script that isn't a PE file is looked at by its name
        std::fs::write(&path, b"text AU3!EA05").unwrap();
        assert!(!is_autoit("x.exe", &path).unwrap());
        assert!(is_autoit("dir/X.AU3", &path).unwrap());
    }
}
