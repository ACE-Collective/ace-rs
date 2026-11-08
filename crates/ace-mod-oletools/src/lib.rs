//! ace3's `OLEVBA_Analyzer_v1_2` and `RTFOLEObjectAnalyzer`, on ports of what they call in oletools
//! 0.60.2, olefile 0.47 and pcodedmp 1.2.6 (PLAN.md 4.10).

pub mod codepage;
pub mod ftguess;
pub mod msoffcrypto;
pub mod ole;
pub mod olevba;
pub mod pcode;
pub mod ppt;
pub mod py;
pub mod pyemail;
pub mod pyxml;
pub mod pyzip;
pub mod rtf;
pub mod scanner;
mod tables;
pub mod textwrap;
pub mod vba;
mod xlm;
pub mod xlmdeob;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use ace_results::types::olevba::{OlevbaAnalysis, OlevbaMacro};
use ace_results::types::rtf::RtfOleObjectAnalysis;
use ace_results::{
    AnalysisType, NewFile, ObservableKind, ObservableRef, Relationship, RelationshipKind,
    ResultEnvelope, YaraMeta,
};
use ace_sdk::{InputFile, Manifest, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::olevba::VbaParser;
use crate::py::{PyErr, strip};

/// The olevba module's manifest.
pub const OLEVBA_MANIFEST: Manifest = Manifest::parser::<Olevba>();
/// The rtfole module's manifest.
pub const RTFOLE_MANIFEST: Manifest = Manifest::parser::<RtfOle>();

/// What both modules may use. ace3's global `maximum_analysis_time`, which is what stops them there.
/// Memory and what crafted files do with it: `docs/measurements/oletools-hostile.md`.
const RESOURCES: Resources = Resources {
    timeout: Duration::from_secs(60),
    memory_mb: 2048,
    cpu_seconds: 60,
};

const SANDBOX: &str = "sandbox";
const OLEVBA_MAX_SIZE: u64 = 4 * 1024 * 1024;
const MAX_SUMMARY_ITEMS: usize = 20;
/// What ace3's command prints first. The Python version is ace3's, so that its report and this are the
/// same text until ace3 changes Python.
const RTFOBJ_BANNER: &str = "rtfobj 0.60.1 on Python 3.14.10 - http://decalage.info/python/oletools\n\
THIS IS WORK IN PROGRESS - Check updates regularly!\n\
Please report any issue at https://github.com/decalage2/oletools/issues\n\n";

/// ace3's `KNOWN_OFFICE_EXTENSIONS`.
const OFFICE_EXTENSIONS: &[&str] = &[
    "doc", "docb", "dochtml", "docm", "docx", "docxml", "dot", "dothtml", "dotm", "dotx", "odt",
    "rtf", "wbk", "wiz", "csv", "dqy", "iqy", "odc", "ods", "slk", "xla", "xlam", "xlk", "xll",
    "xlm", "xls", "xlsb", "xlshtml", "xlsm", "xlsx", "xlt", "xlthtml", "xltm", "xltx", "xlw",
    "odp", "pot", "pothtml", "potm", "potx", "ppa", "ppam", "pps", "ppsm", "ppsx", "ppt",
    "ppthtml", "pptm", "pptx", "pptxml", "pwz", "sldm", "sldx", "thmx",
];

fn is_office_extension(path: &str) -> bool {
    ftguess::splitext(path)
        .1
        .strip_prefix('.')
        .is_some_and(|extension| OFFICE_EXTENSIONS.contains(&extension))
}

fn is_rtf_file(data: &[u8]) -> bool {
    data.starts_with(b"\\rt") || data.starts_with(b"{\\rt")
}

fn is_zip_file(data: &[u8]) -> bool {
    pyzip::ZipFile::new(data).is_ok_and(|zip| !zip.namelist().is_empty())
}

fn yara_type(kind: &str) -> Result<Vec<YaraMeta>, ModuleError> {
    Ok(vec![
        YaraMeta::new("type", kind).map_err(ModuleError::other)?,
    ])
}

fn read_input(local_path: &Path) -> Result<Vec<u8>, ModuleError> {
    Ok(fs::read(local_path)?)
}

/// ace3's `OLEVBA_Analyzer_v1_2`.
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
    const RESOURCES: Resources = RESOURCES;
    type Output = OlevbaAnalysis;
    type Settings = OlevbaSettings;

    fn init(_: &OlevbaSettings) -> Result<Self, ModuleError> {
        Ok(Olevba)
    }
}

/// Why ace3's checks would leave this file alone, if they would.
fn olevba_skip_reason(file: &InputFile, data: &[u8]) -> Option<String> {
    let path = file.path.as_str();
    if is_rtf_file(data) {
        return Some("an RTF file".to_owned());
    }
    if path.to_lowercase().ends_with(".msi") {
        return Some("an MSI file".to_owned());
    }
    if !(is_office_extension(path) || ole::has_magic(data) || is_zip_file(data)) {
        return Some("not an Office, OLE or zip file".to_owned());
    }
    if file.size > OLEVBA_MAX_SIZE {
        return Some("larger than 4 MB".to_owned());
    }
    let mime = file.mime_type.as_deref().unwrap_or_default();
    if mime.contains("html") || mime == "text/plain" {
        return Some(format!("its mime type is {mime}"));
    }
    None
}

/// As ace3 counts them, in its first-seen order. It looks up the kind before lowercasing it, so it
/// starts each count again and every count is 1. The summary and the thresholds read these.
fn keyword_kinds(results: &[scanner::ScanResult]) -> Vec<String> {
    let mut kinds: Vec<String> = Vec::new();
    for (kind, _, _) in results {
        let lower = kind.to_lowercase();
        if !kinds.contains(&lower) {
            kinds.push(lower);
        }
    }
    kinds
}

struct OlevbaRun<'a> {
    ctx: &'a TaskContext<OlevbaSettings>,
    source: ObservableRef,
    files: Vec<NewFile>,
}

impl OlevbaRun<'_> {
    /// ace3's `_add_macro_file`: its record, whose sha256 names what's in it.
    fn add_macro_file(
        &mut self,
        path: &str,
        code: &str,
    ) -> Result<ace_results::Sha256, ModuleError> {
        let mut file =
            self.ctx
                .write_file(path, code.as_bytes(), &yara_type("script.macro.vba")?)?;
        file.add_tag("macro");
        file.add_directive(SANDBOX);
        file.exclude_modules.push(Olevba::NAME.to_owned());
        file.redirection = Some(self.source.clone());
        let sha256 = file.sha256;
        self.files.push(file);
        Ok(sha256)
    }
}

fn text_name(name: Option<&ace_results::bytes::TextOrBytes>) -> ace_results::bytes::TextOrBytes {
    name.cloned()
        .unwrap_or_else(|| ace_results::bytes::TextOrBytes::Text(String::new()))
}

/// The module's `try`, up to what it found and the first exception.
fn olevba_scan(
    file: &InputFile,
    data: Vec<u8>,
    run: &mut OlevbaRun<'_>,
    details: &mut OlevbaAnalysis,
    kinds: &mut Vec<String>,
) -> Result<(), ScanFailure> {
    let path = file.path.as_str();
    let settings = run.ctx.settings();
    let mut parser = VbaParser::open(path, data)?;
    details.kind = parser.kind.map(str::to_owned);
    if !parser.detect_vba_macros()? {
        return Ok(());
    }
    // past the port's own limits what it found is kept, so a file can't lose its macros by adding more
    let mut limit = None;
    let results = match parser.analyze_macros() {
        Ok(results) => results,
        Err(error) if error.kind == "MemoryError" => {
            limit = Some(error);
            Vec::new()
        }
        Err(error) => return Err(error.into()),
    };
    let macros = if limit.is_some() {
        parser.macros_so_far().to_vec()
    } else {
        parser.extract_all_macros()?.to_vec()
    };
    let mut merged = Vec::new();
    let mut index = 0;
    for item in macros {
        let Some(code) = &item.code else {
            // filter_vba(None)
            return Err(PyErr::new(
                "AttributeError",
                "'NoneType' object has no attribute 'splitlines'",
            )
            .into());
        };
        let code = scanner::filter_vba(code);
        if strip(&code).is_empty() {
            continue;
        }
        let stream_path =
            ace_results::bytes::TextOrBytes::Text(item.stream_path.unwrap_or_default());
        let vba_filename = text_name(item.vba_filename.as_ref());
        if settings.merge_macros {
            merged.push((item.file_name, stream_path, vba_filename, code));
        } else {
            let local_path =
                run.add_macro_file(&format!("{path}.olevba/macro_{index}.bas"), &code)?;
            details.macros.push(OlevbaMacro {
                file_name: item.file_name,
                stream_path,
                vba_filename,
                vba_code: code,
                local_path,
            });
        }
        index += 1;
    }
    if !merged.is_empty() {
        let all: String = merged.iter().map(|item| item.3.as_str()).collect();
        let local_path = run.add_macro_file(&format!("{path}.olevba/macros.bas"), &all)?;
        for (file_name, stream_path, vba_filename, vba_code) in merged {
            details.macros.push(OlevbaMacro {
                file_name,
                stream_path,
                vba_filename,
                vba_code,
                local_path,
            });
        }
    }
    *kinds = keyword_kinds(&results);
    details.keyword_summary = kinds.iter().map(|kind| (kind.clone(), 1)).collect();
    limit.map_or(Ok(()), |error| Err(error.into()))
}

/// What ends the module's `try`: a Python exception, which it handles, or the task's own failure.
enum ScanFailure {
    Raised(PyErr),
    Task(ModuleError),
}

impl From<PyErr> for ScanFailure {
    fn from(error: PyErr) -> Self {
        ScanFailure::Raised(error)
    }
}

impl From<ModuleError> for ScanFailure {
    fn from(error: ModuleError) -> Self {
        ScanFailure::Task(error)
    }
}

impl Parser for Olevba {
    fn analyze(
        &self,
        ctx: &TaskContext<OlevbaSettings>,
    ) -> Result<Outcome<OlevbaAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let data = read_input(&file.local_path)?;
        if let Some(reason) = olevba_skip_reason(file, &data) {
            return Ok(Outcome::Skipped(reason));
        }
        let path = file.path.as_str();
        let mut details = OlevbaAnalysis::default();
        let mut kinds = Vec::new();
        let mut run = OlevbaRun {
            ctx,
            source: ObservableRef::new(ObservableKind::File, file.sha256.to_hex()),
            files: Vec::new(),
        };
        let scan = olevba_scan(file, data, &mut run, &mut details, &mut kinds);
        let OlevbaRun { files, .. } = run;
        let mut tags_and_directive = None;
        match scan {
            Ok(()) => {
                let thresholds = &ctx.settings().thresholds;
                let met = thresholds.iter().all(|(kind, &count)| {
                    details
                        .keyword_summary
                        .get(kind)
                        .is_some_and(|&found| found >= count)
                });
                if !kinds.is_empty() && met {
                    tags_and_directive = Some("olevba");
                }
            }
            Err(ScanFailure::Task(error)) => return Err(error),
            Err(ScanFailure::Raised(error)) => {
                tracing::warn!(%error, %path, "olevba execution error");
                if is_office_extension(path) {
                    tags_and_directive = Some("olevba_failed");
                }
            }
        }
        let summary = match (&details.kind, details.macros.is_empty()) {
            (Some(kind), false) => {
                let counts: Vec<String> = kinds.iter().map(|kind| format!("{kind}=1")).collect();
                Some(format!(
                    "OLEVBA Analysis: ({} macro files) ({kind}) | {}",
                    details.macros.len(),
                    counts.join(", ")
                ))
            }
            _ => None,
        };
        let mut result = ResultEnvelope::new(details);
        result.summary = summary;
        result.files = files;
        if let Some(tag) = tags_and_directive {
            result.analyzed.add_tag(tag);
            result.analyzed.add_directive(SANDBOX);
        }
        Ok(Outcome::Done(result))
    }
}

/// ace3's `RTFOLEObjectAnalyzer`, on the port of rtfobj. The other two modules in `rtf.py` don't use
/// oletools, so they aren't here.
pub struct RtfOle;

impl Module for RtfOle {
    const NAME: &'static str = RtfOleObjectAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    // ace3's run_tool stops the command 5 s before maximum_analysis_time and keeps an empty result;
    // here the task fails at the deadline.
    const RESOURCES: Resources = RESOURCES;
    type Output = RtfOleObjectAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(RtfOle)
    }
}

fn rtf_summary(extracted: &[String]) -> Option<String> {
    if extracted.is_empty() {
        return None;
    }
    let mut names = extracted
        .iter()
        .take(MAX_SUMMARY_ITEMS)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if extracted.len() > MAX_SUMMARY_ITEMS {
        names.push_str(&format!(" + {} more", extracted.len() - MAX_SUMMARY_ITEMS));
    }
    Some(format!("RTF OLE Object Analysis: extracted {names}"))
}

impl Parser for RtfOle {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<RtfOleObjectAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        if file.size == 0 {
            return Ok(Outcome::Skipped("an empty file".to_owned()));
        }
        let data = read_input(&file.local_path)?;
        if !is_rtf_file(&data) {
            return Ok(Outcome::Skipped("not an RTF file".to_owned()));
        }
        let path = file.path.as_str();
        let alert_dir = format!("{path}.rtfobj");
        let mut report = rtf::process_file(path, &data, &alert_dir, rtf::Limits::TASK);
        report.files.sort_by(|a, b| a.0.cmp(&b.0));

        let source = ObservableRef::new(ObservableKind::File, file.sha256.to_hex());
        let mut extracted_files = Vec::with_capacity(report.files.len());
        let mut files = Vec::with_capacity(report.files.len());
        for (name, bytes) in &report.files {
            let object_path = format!("{alert_dir}/{name}");
            let mut new_file =
                ctx.write_file(&object_path, bytes, &yara_type("document.rtf.object")?)?;
            new_file.add_tag("extracted_rtf");
            new_file.redirection = Some(source.clone());
            new_file.relationships.push(Relationship::new(
                RelationshipKind::ExtractedFrom,
                source.clone(),
            ));
            extracted_files.push(object_path);
            files.push(new_file);
        }
        let (stderr, return_code) = match &report.raised {
            None => (String::new(), 0),
            // what a traceback ends with: ace3's frames name its own node, so they couldn't match
            Some(error) if error.message.is_empty() => (format!("{}\n", error.kind), 1),
            Some(error) => (format!("{}: {}\n", error.kind, error.message), 1),
        };
        // text mode, as ace3 reads the command's pipe
        let stdout = format!("{RTFOBJ_BANNER}{}", report.stdout)
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        let summary = rtf_summary(&extracted_files);
        let mut result = ResultEnvelope::new(RtfOleObjectAnalysis {
            stdout,
            stderr,
            return_code,
            extracted_files,
        });
        result.summary = summary;
        result.files = files;
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use ace_sdk::Outcome;
    use ace_testkit::Harness;

    use super::*;

    const DOC: &str = "ace3/office/receipt_687790.doc";

    fn olevba(sample: &str, settings: OlevbaSettings) -> Outcome<OlevbaAnalysis> {
        let block = serde_json::json!({"merge_macros": settings.merge_macros, "thresholds": settings.thresholds});
        let harness = Harness::<Olevba>::with_settings(block).expect("harness");
        let input = harness.sample(sample).expect("a sample");
        harness.run_parser(input).expect("runs")
    }

    fn done<T>(outcome: Outcome<T>) -> ResultEnvelope<T> {
        match outcome {
            Outcome::Done(result) => result,
            _ => panic!("not done"),
        }
    }

    fn rtfole(sample: &str) -> Outcome<RtfOleObjectAnalysis> {
        let harness = Harness::<RtfOle>::new().expect("harness");
        let input = harness.sample(sample).expect("a sample");
        harness.run_parser(input).expect("runs")
    }

    #[test]
    fn macros_become_files_with_ace3s_names_tags_and_directives() {
        let outcome = olevba(DOC, OlevbaSettings::default());
        // the fixture ace-gui's analysis view test draws (PLAN.md 5.9)
        ace_testkit::check_view_fixture("olevba_receipt_doc", &outcome);
        let result = done(outcome);
        assert_eq!(result.details.kind.as_deref(), Some("OLE"));
        assert_eq!(result.details.macros.len(), 5);
        assert_eq!(result.analyzed.tags, ["olevba"]);
        assert_eq!(result.analyzed.directives, [SANDBOX]);
        let summary = result.summary.expect("a summary");
        assert!(
            summary.starts_with("OLEVBA Analysis: (5 macro files) (OLE) | "),
            "{summary}"
        );
        for (index, (item, file)) in result.details.macros.iter().zip(&result.files).enumerate() {
            assert_eq!(
                file.path.as_str(),
                format!("receipt_687790.doc.olevba/macro_{index}.bas")
            );
            assert_eq!(file.tags, ["macro"]);
            assert_eq!(file.directives, [SANDBOX]);
            assert_eq!(file.exclude_modules, ["olevba_v1_2"]);
            assert_eq!(item.local_path, file.sha256);
            assert_eq!(
                item.file_name,
                Some(ace_results::bytes::TextOrBytes::Text(
                    "receipt_687790.doc".to_owned()
                ))
            );
            assert!(file.redirection.is_some());
        }
    }

    #[test]
    fn every_count_is_one_as_in_ace3() {
        let rows = [("AutoExec", "a"), ("AutoExec", "b"), ("IOC", "c")]
            .map(|(kind, value)| (kind.to_owned(), value.to_owned(), String::new()));
        assert_eq!(keyword_kinds(&rows), ["autoexec", "ioc"]);
    }

    #[test]
    fn a_stomped_document_has_its_p_code_as_a_macro_and_the_keyword() {
        let result = done(olevba(
            "ace3/office/word2013_macro_stripped.doc",
            OlevbaSettings::default(),
        ));
        let pcode = result
            .details
            .macros
            .iter()
            .find(|item| {
                item.stream_path == ace_results::bytes::TextOrBytes::Text("VBA P-code".to_owned())
            })
            .expect("the p-code");
        assert!(
            pcode
                .vba_code
                .starts_with("' Processing file: word2013_macro_stripped.doc\n")
        );
        assert_eq!(result.analyzed.tags, ["olevba"]);
    }

    #[test]
    fn merged_macros_share_one_file() {
        let settings = OlevbaSettings {
            merge_macros: true,
            ..OlevbaSettings::default()
        };
        let result = done(olevba(DOC, settings));
        assert_eq!(result.files.len(), 1);
        assert_eq!(
            result.files[0].path.as_str(),
            "receipt_687790.doc.olevba/macros.bas"
        );
        assert!(
            result
                .details
                .macros
                .iter()
                .all(|item| item.local_path == result.files[0].sha256)
        );
    }

    #[test]
    fn a_threshold_not_met_leaves_no_tag() {
        let settings = OlevbaSettings {
            thresholds: BTreeMap::from([("dridex string".to_owned(), 1)]),
            ..Default::default()
        };
        let result = done(olevba(DOC, settings));
        assert!(result.analyzed.tags.is_empty());
        assert_eq!(result.details.macros.len(), 5);
    }

    fn input(path: &str, size: u64, mime: Option<&str>) -> InputFile {
        InputFile {
            path: ace_results::AlertPath::new(path).expect("a path"),
            sha256: ace_results::Sha256([0; 32]),
            size,
            yara_meta: Vec::new(),
            mime_type: mime.map(str::to_owned),
            local_path: Default::default(),
        }
    }

    #[test]
    fn what_ace3_checks_before_it_opens_a_file() {
        let ole = crate::ole::MAGIC;
        for (file, data) in [
            (input("a.doc", 8, None), &b"{\\rtf1 x}"[..]),
            (input("A.MSI", 8, None), &ole[..]),
            (input("a.txt", 8, None), &b"just text"[..]),
            (input("a.doc", OLEVBA_MAX_SIZE + 1, None), &ole[..]),
            (input("a.doc", 8, Some("text/html")), &b"<html>"[..]),
            (input("a.doc", 8, Some("text/plain")), &b"text"[..]),
        ] {
            assert!(
                olevba_skip_reason(&file, data).is_some(),
                "{}",
                file.path.as_str()
            );
        }
        assert!(olevba_skip_reason(&input("a.doc", 8, Some("application/x")), b"x").is_none());
    }

    #[test]
    fn a_file_oletools_cant_open_fails_only_under_an_office_extension() {
        let result = done(olevba("ace4/office/garbage.doc", OlevbaSettings::default()));
        assert_eq!(result.analyzed.tags, ["olevba_failed"]);
        assert_eq!(result.analyzed.directives, [SANDBOX]);
        assert_eq!(result.details.kind, None);
        let zipped = done(olevba("ace3/archive/test.jar", OlevbaSettings::default()));
        assert!(zipped.analyzed.tags.is_empty());
    }

    #[test]
    fn a_hostile_name_stays_bytes() {
        let result = done(olevba(
            "ace4/office/surrogate_name.doc",
            OlevbaSettings::default(),
        ));
        let item = &result.details.macros[0];
        assert_eq!(
            serde_json::to_value(&item.file_name).expect("json"),
            serde_json::json!({"base64": "7aCALm1zbw=="})
        );
        assert_eq!(
            item.stream_path,
            ace_results::bytes::TextOrBytes::Text("VBA/ThisDocument".to_owned())
        );
    }

    #[test]
    fn a_ppt_macro_has_no_file_name_as_in_ace3() {
        let result = done(olevba(
            "ace4/office/vba_powerpoint.ppt",
            OlevbaSettings::default(),
        ));
        assert_eq!(result.details.kind.as_deref(), Some("PPT"));
        assert!(!result.details.macros.is_empty());
        assert_eq!(result.details.macros[0].file_name, None);
    }

    #[test]
    fn a_macro_sheet_beside_vba_is_a_macro_file_too() {
        let result = done(olevba(
            "ace4/office/vba_xlm_biff8.xls",
            OlevbaSettings::default(),
        ));
        assert_eq!(result.analyzed.tags, ["olevba"]);
        assert!(result.details.keyword_summary.contains_key("suspicious"));
        let names: Vec<String> = result
            .details
            .macros
            .iter()
            .map(|item| format!("{:?}", item.vba_filename))
            .collect();
        assert!(
            names.iter().any(|name| name.contains("xlm_macro.txt")),
            "{names:?}"
        );
    }

    #[test]
    fn objects_become_files_with_ace3s_names_tags_and_links() {
        let Outcome::Done(result) = rtfole("ace4/rtf/objects.rtf") else {
            panic!("not done")
        };
        let details = &result.details;
        assert_eq!(details.return_code, 0);
        assert_eq!(details.stderr, "");
        let names: Vec<&str> = result.files.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(
            names,
            details
                .extracted_files
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        );
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
        for name in [
            "payload.exe",
            "._._evil.exe",
            "caf\u{e9}.txt",
            "inner.zip",
            "inner.rtf",
        ] {
            assert!(
                names.contains(&format!("objects.rtf.rtfobj/objects.rtf_{name}").as_str()),
                "{name}"
            );
        }
        for file in &result.files {
            assert_eq!(file.tags, ["extracted_rtf"]);
            assert_eq!(file.relationships.len(), 1);
            assert!(file.redirection.is_some());
        }
    }

    #[test]
    fn the_report_is_the_commands() {
        let outcome = rtfole("ace4/rtf/objects.rtf");
        // the fixture ace-gui's analysis view test draws (PLAN.md 5.9)
        ace_testkit::check_view_fixture("rtfole_objects_rtf", &outcome);
        let Outcome::Done(result) = outcome else {
            panic!("not done")
        };
        let stdout = &result.details.stdout;
        assert!(
            stdout.starts_with("rtfobj 0.60.1 on Python "),
            "{}",
            &stdout[..80]
        );
        assert!(stdout.contains("File: 'objects.rtf' - size: "));
        assert!(stdout.contains("id |index     |OLE Object"));
        assert!(stdout.contains("EXECUTABLE FILE"));
        assert!(stdout.contains("URL extracted: http://example.com/a.hta"));
        assert!(stdout.contains("  saving to file objects.rtf.rtfobj/objects.rtf_payload.exe\n"));
    }

    #[test]
    fn an_exception_is_an_exit_code_and_what_was_saved_stays() {
        let Outcome::Done(result) = rtfole("ace4/rtf/bin_at_end.rtf") else {
            panic!("not done")
        };
        assert_eq!(result.details.return_code, 1);
        assert!(
            result
                .details
                .stderr
                .contains("TypeError: ord() expected a character")
        );
        assert!(result.details.extracted_files.is_empty());

        let Outcome::Done(result) = rtfole("ace4/rtf/long_name.rtf") else {
            panic!("not done")
        };
        assert_eq!(result.details.return_code, 1);
        assert!(
            result
                .details
                .stderr
                .contains("File name too long: 'long_name.rtf.rtfobj/long_name.rtf_")
        );
        assert_eq!(
            result.details.extracted_files,
            ["long_name.rtf.rtfobj/long_name.rtf_saved.txt"]
        );
    }

    #[test]
    fn a_name_with_glob_characters_is_read() {
        let Outcome::Done(result) = rtfole("ace4/rtf/bracket[1].rtf") else {
            panic!("not done")
        };
        assert_eq!(
            result.details.extracted_files,
            ["bracket[1].rtf.rtfobj/bracket_1_.rtf_payload.exe"]
        );
    }

    #[test]
    fn what_ace3_checks_before_it_reads_a_rtf() {
        assert!(matches!(
            rtfole("ace4/rtf/text_named.rtf"),
            Outcome::Skipped(_)
        ));
        let Outcome::Done(result) = rtfole("ace4/rtf/backslash_start.rtf") else {
            panic!("not done")
        };
        assert_eq!(result.files.len(), 1);
        let Outcome::Done(result) = rtfole("ace4/rtf/no_objects.rtf") else {
            panic!("not done")
        };
        assert!(result.details.extracted_files.is_empty());
        assert!(result.summary.is_none());
    }

    #[test]
    fn the_summary_lists_twenty() {
        assert_eq!(
            rtf_summary(&["a".to_owned(), "b".to_owned()]).as_deref(),
            Some("RTF OLE Object Analysis: extracted a, b")
        );
        let names: Vec<String> = (0..22).map(|n| n.to_string()).collect();
        let first: Vec<&str> = names[..20].iter().map(String::as_str).collect();
        assert_eq!(
            rtf_summary(&names),
            Some(format!(
                "RTF OLE Object Analysis: extracted {} + 2 more",
                first.join(", ")
            ))
        );
    }

    #[test]
    fn the_manifests_are_parsers_with_the_keys_ace3s_modes_name() {
        assert_eq!(Olevba::NAME, "olevba_v1_2");
        assert_eq!(RtfOle::NAME, "rtfole");
    }
}
