//! ace3's `XLMMacroDeobfuscatorAnalyzer` (`saq/modules/file_analysis/xlm.py`) and `PCodeAnalyzer`
//! (`saq/modules/file_analysis/vbs.py`), on the ports in `ace-mod-oletools`.
//!
//! ace3 runs the xlmdeobfuscator command twice. `-f` emulates the macro from its Auto_Open, which shows a
//! URL a macro only builds when it runs, and `-x` lists the cells with no emulation, which still works
//! when emulation can't: the tags and the cell count come from that one. ace3 gives each pass 30 s and
//! past that drops what the pass printed, tags the file and goes on, so a macro that spins still has its
//! cells listed. Here emulation reads its clock inside the interpreter's loop, and a pass past its output
//! limit is dropped the same way.
//!
//! It's a separate crate from `ace-mod-oletools` because it links yara-x, for ace3's rule file.

use std::path::Path;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use ace_mod_oletools::olevba::pcodedmp_process_file;
use ace_mod_oletools::xlmdeob::run_command;
use ace_results::types::file_type::FileTypeAnalysis;
use ace_results::types::pcode::PCodeAnalysis;
use ace_results::types::xlm::XlmDeobfuscatorAnalysis;
use ace_results::{
    AnalysisType, Detection, NewFile, NewObservable, ObservableKind, ObservableRef, ResultEnvelope,
    YaraMeta,
};
use ace_sdk::takes::{Case, Condition, Match, Takes, Text};
use ace_sdk::{InputFile, Manifest, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const XLM_MANIFEST: Manifest = Manifest::parser::<XlmDeobfuscator>();
pub const PCODE_MANIFEST: Manifest = Manifest::parser::<PCode>();

/// ace3's built-in XLM_MACRO_URL signature.
const SIGNATURE_UUID: &str = "3e719b5d-8063-4cd7-a72b-3d1cc8ead39c";
const DETECTION: &str = "A url was found in an Excel 4.0 macro.";
/// What ace3 looks for to stop after a pass. The library names the file there, so this is only ever
/// found for a file called this; the library's message is otherwise a pass like any other.
const ENCRYPTED_TEXT: &str =
    "Failed to decrypt the file\nUse --password switch to provide the correct password";

/// ace3's etc/xlmdeobfuscator.yar. Rules tagged xlm4 say a file has Excel 4.0 macros.
const RULES: &str = include_str!("xlmdeobfuscator.yar");

fn read_input(path: &Path) -> Result<Vec<u8>, ModuleError> {
    std::fs::read(path)
        .map_err(|error| ModuleError::other(format!("unable to read {}: {error}", path.display())))
}

fn yara_type(kind: &str) -> Result<Vec<YaraMeta>, ModuleError> {
    Ok(vec![
        YaraMeta::new("type", kind).map_err(ModuleError::other)?,
    ])
}

pub struct XlmDeobfuscator;

/// ace3's settings of the module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct XlmDeobfuscatorSettings {
    /// How long each of its two passes may take, in seconds. Two of these, and a little, must fit in
    /// the manifest's deadline, or the deadline ends the module before this does.
    pub timeout: u64,
    /// The largest file it reads, in MB.
    pub maximum_size_mb: u64,
    /// YARA rules, by name, that make it analyze a file when they match the file or anything below
    /// it. Its own rules, in `xlmdeobfuscator.yar`, do too.
    pub yara_rule_names: Vec<String>,
}

impl Default for XlmDeobfuscatorSettings {
    fn default() -> Self {
        XlmDeobfuscatorSettings {
            timeout: 30,
            maximum_size_mb: 10,
            yara_rule_names: [
                "Content_Types_Macrosheet",
                "XLM_Macrosheet_NonBin",
                "Possible_XLM_in_XLSB",
            ]
            .map(str::to_owned)
            .to_vec(),
        }
    }
}

impl Module for XlmDeobfuscator {
    const NAME: &'static str = XlmDeobfuscatorAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const RUNS_LAST: bool = true;
    // Two passes of the 30 s ace3 gives each, which the module enforces itself, and time to read the
    // file and write the result. CPU is the same, since a spinning macro uses all of it. 1536 MB is what
    // the interpreter's limits and two passes of output need: docs/measurements/xlm-hostile.md.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(75),
        memory_mb: 2048,
        cpu_seconds: 75,
    };
    type Output = XlmDeobfuscatorAnalysis;
    type Settings = XlmDeobfuscatorSettings;

    fn init(_: &XlmDeobfuscatorSettings) -> Result<Self, ModuleError> {
        Ok(XlmDeobfuscator)
    }
}

/// ace3's own rules, compiled on the first file that needs them. A pool builds every module for every
/// task, so this isn't in `init`.
static COMPILED: LazyLock<Result<yara_x::Rules, String>> = LazyLock::new(|| {
    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(RULES)
        .map_err(|error| format!("xlmdeobfuscator.yar: {error}"))?;
    Ok(compiler.build())
});

/// Whether ace3 would analyze this file: its own rules, or the YARA module's in it or below it.
fn has_macros(
    data: &[u8],
    rules_below: &[String],
    rule_names: &[String],
) -> Result<bool, ModuleError> {
    if rules_below.iter().any(|rule| rule_names.contains(rule)) {
        return Ok(true);
    }
    let rules = COMPILED
        .as_ref()
        .map_err(|error| ModuleError::other(error.clone()))?;
    let mut scanner = yara_x::Scanner::new(rules);
    let results = scanner
        .scan(data)
        .map_err(|error| ModuleError::other(format!("the scan failed: {error}")))?;
    Ok(results
        .matching_rules()
        .any(|rule| rule.tags().any(|tag| tag.identifier() == "xlm4")))
}

/// ace3's `_extract_urls`: the URLs passed as parameters in the macro's cells.
fn urls_in(stdout: &str, urls: &mut Vec<String>) {
    static PARAMS: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^CELL:.*\(([^\)]*)\)$").expect("a valid expression"));
    static URL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"(?i)https?://[^"]+"#).expect("a valid expression"));
    for line in stdout.split('\n') {
        if line.starts_with("CELL:")
            && let Some(params) = PARAMS.captures(line)
        {
            urls.extend(URL.find_iter(&params[1]).map(|m| m.as_str().to_owned()));
        }
    }
}

/// ace3's URLObservable refuses a URL with no host, which is text an attacker wrote, and keeps one
/// `urlsplit` can't read. The core doesn't check them.
pub fn names_a_host(url: &str) -> bool {
    let Ok((scheme, _)) = urlsplit(url) else {
        return true;
    };
    if !matches!(scheme.as_str(), "http" | "https" | "ftp") {
        return true;
    }
    let rest: String = url
        .split_once(':')
        .map_or("", |(_, rest)| rest)
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let rest = rest.replace('\\', "/");
    let rest = rest.trim_start_matches('/');
    match urlsplit(&format!("{scheme}://{rest}")) {
        Ok((_, netloc)) => hostname(&netloc).chars().any(char::is_alphanumeric),
        Err(()) => true,
    }
}

/// `urlsplit`'s scheme and netloc, or Err for its ValueError. The check for a netloc that NFKC turns into
/// a delimiter isn't here: such a host still has what the module asks of it.
fn urlsplit(url: &str) -> Result<(String, String), ()> {
    let url = url.trim_start_matches(|c: char| c <= ' ');
    let url: String = url
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut rest = url.as_str();
    let mut scheme = String::new();
    if let Some(at) = rest.find(':')
        && at > 0
        && rest.as_bytes()[0].is_ascii_alphabetic()
        && rest[..at]
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
    {
        scheme = rest[..at].to_ascii_lowercase();
        rest = &rest[at + 1..];
    }
    let mut netloc = String::new();
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        netloc = after[..end].to_owned();
        let (open, close) = (netloc.contains('['), netloc.contains(']'));
        if open != close {
            return Err(());
        }
        if open {
            check_bracketed(&netloc)?;
        }
    }
    Ok((scheme, netloc))
}

fn check_bracketed(netloc: &str) -> Result<(), ()> {
    let host_port = netloc.rsplit_once('@').map_or(netloc, |(_, host)| host);
    let host = if let Some((before, bracketed)) = host_port.split_once('[') {
        if !before.is_empty() {
            return Err(());
        }
        let (host, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
        if !port.is_empty() && !port.starts_with(':') {
            return Err(());
        }
        host
    } else {
        host_port
            .split_once(':')
            .map_or(host_port, |(host, _)| host)
    };
    if let Some(version) = host.strip_prefix('v') {
        let (hex, tail) = version.split_once('.').ok_or(())?;
        if hex.is_empty() || !hex.bytes().all(|c| c.is_ascii_hexdigit()) || tail.is_empty() {
            return Err(());
        }
        return Ok(());
    }
    host.parse::<std::net::Ipv6Addr>().map(drop).map_err(drop)
}

/// `SplitResult.hostname`.
fn hostname(netloc: &str) -> String {
    let after = netloc.rsplit_once('@').map_or(netloc, |(_, host)| host);
    let host = if let Some((_, bracketed)) = after.split_once('[') {
        bracketed
            .split_once(']')
            .map_or(bracketed, |(host, _)| host)
    } else {
        after.split_once(':').map_or(after, |(host, _)| host)
    };
    match host.split_once('%') {
        Some((name, zone)) => format!("{}%{zone}", name.to_lowercase()),
        None => host.to_lowercase(),
    }
}

/// One pass's bytes as the module keeps them, or None when it was dropped.
struct Passes<'a> {
    ctx: &'a TaskContext<XlmDeobfuscatorSettings>,
    data: &'a [u8],
    path: &'a str,
    timeout: Duration,
    tags: Vec<&'static str>,
    files: Vec<NewFile>,
    urls: Vec<String>,
}

impl Passes<'_> {
    fn run(&mut self, extract_only: bool, failed_tag: &'static str) -> Option<String> {
        let pass = run_command(
            self.data,
            self.path,
            extract_only,
            Some(Instant::now() + self.timeout),
        );
        if pass.dropped {
            self.tags.push(failed_tag);
            return None;
        }
        Some(pass.stdout)
    }

    fn add_output(&mut self, name: &str, stdout: &str) -> Result<(), ModuleError> {
        let path = format!("{}.xlmdeobfuscator/{name}", self.path);
        let mut file =
            self.ctx
                .write_file(&path, stdout.as_bytes(), &yara_type("script.macro.xlm")?)?;
        file.add_directive("extract_urls");
        file.add_directive("crawl_extracted_urls");
        self.files.push(file);
        urls_in(stdout, &mut self.urls);
        Ok(())
    }
}

impl Parser for XlmDeobfuscator {
    fn analyze(
        &self,
        ctx: &TaskContext<XlmDeobfuscatorSettings>,
    ) -> Result<Outcome<XlmDeobfuscatorAnalysis>, ModuleError> {
        let file: &InputFile = ctx.input_file()?;
        let settings = ctx.settings();
        if file.size > settings.maximum_size_mb.saturating_mul(1024 * 1024) {
            return Ok(Outcome::Skipped(format!(
                "larger than {} MB",
                settings.maximum_size_mb
            )));
        }
        let data = read_input(&file.local_path)?;
        if !has_macros(&data, ctx.yara_rules_below(), &settings.yara_rule_names)? {
            return Ok(Outcome::Skipped("no Excel 4.0 macros".to_owned()));
        }
        let mut passes = Passes {
            ctx,
            data: &data,
            path: file.path.as_str(),
            timeout: Duration::from_secs(settings.timeout),
            tags: Vec::new(),
            files: Vec::new(),
            urls: Vec::new(),
        };
        let mut cell_count = 0;
        let mut stop = false;
        if let Some(stdout) = passes.run(false, "xlmdeobfuscator_failed") {
            if stdout.contains(ENCRYPTED_TEXT) {
                stop = true;
            } else {
                passes.add_output("xlmdeobfuscator.stdout", &stdout)?;
            }
        }
        if !stop
            && let Some(stdout) = passes.run(true, "xlmdeobfuscatorextractcells_failed")
            && !stdout.contains(ENCRYPTED_TEXT)
        {
            passes.add_output("xlmdeobfuscatorextractcells.stdout", &stdout)?;
            cell_count = stdout.matches("\nCELL:").count() as u64;
            passes.tags.push(if cell_count > 0 {
                "xlm4"
            } else {
                "xlm4:no_cells"
            });
            if stdout.contains("\nError ") {
                passes.tags.push("xlm4:error");
            }
        }
        let Passes {
            tags, files, urls, ..
        } = passes;
        let mut result = ResultEnvelope::new(XlmDeobfuscatorAnalysis { cell_count });
        result.summary = Some(format!(
            "XLMMacroDeobfuscator Analysis - analyzed {cell_count} cells"
        ));
        for tag in tags {
            result.analyzed.add_tag(tag);
        }
        if !urls.is_empty() {
            // one, however many URLs: ace3 keeps one detection point per description
            let mut detection = Detection::new(DETECTION);
            detection.signature_uuid = Some(SIGNATURE_UUID.to_owned());
            result.analyzed.detections.push(detection);
        }
        let mut seen = Vec::new();
        for url in urls {
            if !seen.contains(&url) && names_a_host(&url) {
                let mut observable = NewObservable::new(ObservableKind::Url, url.clone());
                observable.directives.push("crawl".to_owned());
                result.observables.push(observable);
            }
            seen.push(url);
        }
        result.files = files;
        Ok(Outcome::Done(result))
    }
}

/// ace3's `PCodeAnalyzer`. `VBScriptAnalyzer` in `vbs.py` doesn't use pcodedmp and stays for 7.5.
pub struct PCode;

impl Module for PCode {
    const NAME: &'static str = PCodeAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    /// ace3's `is_office_file` reads file_type's description of the file.
    const DEPENDS_ON: &'static [&'static str] = &[FileTypeAnalysis::MODULE];
    // The 30 s bin/pcodedmp_wrapper gives pcodedmp. ace3 then keeps nothing and says so in a log; here
    // the task fails, with its stack in the row.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(30),
        memory_mb: 2048,
        cpu_seconds: 30,
    };
    type Output = PCodeAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(PCode)
    }

    fn takes(_: &()) -> Takes {
        // ace3's is_office_file: by the extension, or by what file_type's libmagic description calls
        // the file
        let mut office: Vec<Condition> = vec![Condition::Extension(Text::exact(Match::OneOf(
            KNOWN_OFFICE_EXTENSIONS
                .iter()
                .map(|ext| format!(".{ext}"))
                .collect(),
        )))];
        office.extend(OFFICE_DESCRIPTIONS.iter().map(|name| {
            Condition::result_text(
                FileTypeAnalysis::MODULE,
                "type",
                Text::new(Match::Contains((*name).to_owned()), Case::Lower),
            )
        }));
        Takes::everything().and(Condition::Any(office), "not an Office file")
    }
}

const KNOWN_OFFICE_EXTENSIONS: &[&str] = &[
    "doc", "docb", "dochtml", "docm", "docx", "docxml", "dot", "dothtml", "dotm", "dotx", "odt",
    "rtf", "wbk", "wiz", "csv", "dqy", "iqy", "odc", "ods", "slk", "xla", "xlam", "xlk", "xll",
    "xlm", "xls", "xlsb", "xlshtml", "xlsm", "xlsx", "xlt", "xlthtml", "xltm", "xltx", "xlw",
    "odp", "pot", "pothtml", "potm", "potx", "ppa", "ppam", "pps", "ppsm", "ppsx", "ppt",
    "ppthtml", "pptm", "pptx", "pptxml", "pwz", "sldm", "sldx", "thmx",
];

/// `os.path.splitext`'s extension of a name, without its dot: a name's leading dots aren't one.
/// What file_type's libmagic description of an Office file contains, lowered: the other half of
/// ace3's is_office_file.
const OFFICE_DESCRIPTIONS: [&str; 5] = [
    "microsoft powerpoint",
    "microsoft excel",
    "microsoft word",
    "microsoft ooxml",
    "opendocument",
];

/// bin/pcodedmp_wrapper's `sed -ne '/^Module streams:/,$ p' | egrep '^[[:space:]]'`. A newline is the only
/// thing that ends a line, whatever a string in the macro holds. `[[:space:]]` is the C.UTF-8 locale's.
pub fn disassembly(text: &str) -> String {
    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    let Some(start) = lines
        .iter()
        .position(|line| line.starts_with("Module streams:"))
    else {
        return String::new();
    };
    let mut kept = String::new();
    for line in &lines[start..] {
        if line.chars().next().is_some_and(is_posix_space) {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    kept
}

fn is_posix_space(c: char) -> bool {
    // what glibc's C.UTF-8 calls space: Unicode's White_Space without the no-break spaces
    matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | '\u{1680}' | '\u{2000}'..='\u{2006}'
        | '\u{2008}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{205f}' | '\u{3000}')
}

impl Parser for PCode {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<PCodeAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let data = read_input(&file.local_path)?;
        let (text, _) = pcodedmp_process_file(file.path.as_str(), data, false);
        let code = disassembly(&text);
        if code.is_empty() {
            return Ok(Outcome::Skipped("no p-code".to_owned()));
        }
        let line_count = code.matches('\n').count() as u64;
        let path = format!("{}.pcode.bas", file.path.as_str());
        let mut output = ctx.write_file(&path, code.as_bytes(), &yara_type("script.vbscript")?)?;
        output.redirection = Some(ObservableRef::new(
            ObservableKind::File,
            file.sha256.to_hex(),
        ));
        let mut result = ResultEnvelope::new(PCodeAnalysis { line_count });
        result.summary = Some(format!("PCode Analysis: decoded {line_count} lines"));
        result.files = vec![output];
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use ace_testkit::Harness;
    use serde_json::json;

    use super::*;

    fn run(sample: &str, settings: serde_json::Value) -> Outcome<XlmDeobfuscatorAnalysis> {
        let harness = Harness::<XlmDeobfuscator>::with_settings(settings).expect("harness");
        let input = harness.sample(sample).expect("a sample");
        harness.run_parser(input).expect("runs")
    }

    fn done(sample: &str) -> ResultEnvelope<XlmDeobfuscatorAnalysis> {
        match run(sample, json!({})) {
            Outcome::Done(result) => result,
            _ => panic!("{sample} wasn't analyzed"),
        }
    }

    #[test]
    fn a_macro_that_builds_its_url_is_emulated_and_its_cells_listed() {
        // the fixture ace-gui's analysis view test draws (PLAN.md 5.9)
        ace_testkit::check_view_fixture(
            "xlm_obfuscated_xlsm",
            &run("ace4/office/xlm_obfuscated.xlsm", json!({})),
        );
        let result = done("ace4/office/xlm_obfuscated.xlsm");
        assert_eq!(result.details.cell_count, 13);
        assert_eq!(
            result.summary.as_deref(),
            Some("XLMMacroDeobfuscator Analysis - analyzed 13 cells")
        );
        assert_eq!(result.analyzed.tags, ["xlm4"]);
        assert_eq!(result.analyzed.detections.len(), 1);
        assert_eq!(result.files.len(), 2);
        for file in &result.files {
            assert_eq!(file.directives, ["extract_urls", "crawl_extracted_urls"]);
        }
        let mut values: Vec<&str> = result
            .observables
            .iter()
            .map(|o| o.value.as_str())
            .collect();
        values.sort_unstable();
        assert_eq!(
            values,
            [
                "HTTP://Upper.example.com/a b",
                "http://xlm-built.example.com/stage2.exe",
                "https://xlm-plain.example.com/a?b=1",
            ]
        );
        assert!(result.observables.iter().all(|o| o.directives == ["crawl"]));
    }

    #[test]
    fn each_format_is_read() {
        for (name, cells, url) in [
            (
                "xlm_biff8.xls",
                5,
                "http://xlm-biff8.example.com/stage2.exe",
            ),
            ("xlm_xlsb.xlsb", 3, "http://xlm-xlsb.example.com/stage2.exe"),
        ] {
            let result = done(&format!("ace4/office/{name}"));
            assert_eq!(result.details.cell_count, cells, "{name}");
            assert!(result.observables.iter().any(|o| o.value == url), "{name}");
        }
    }

    #[test]
    fn no_cells_and_a_workbook_that_wont_load_have_their_tags() {
        assert_eq!(
            done("ace4/office/xlm_no_cells.xlsm").analyzed.tags,
            ["xlm4:no_cells"]
        );
        assert_eq!(
            done("ace4/office/xlm_broken.xlsm").analyzed.tags,
            ["xlm4:no_cells", "xlm4:error"]
        );
    }

    #[test]
    fn a_pass_out_of_time_is_tagged_and_the_next_still_runs() {
        let started = Instant::now();
        let Outcome::Done(result) = run("ace4/office/xlm_loop.xlsm", json!({"timeout": 1})) else {
            panic!("not analyzed");
        };
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(result.analyzed.tags, ["xlmdeobfuscator_failed", "xlm4"]);
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.details.cell_count, 5);
    }

    #[test]
    fn only_a_file_with_macros_and_under_the_limit_is_read() {
        let names = XlmDeobfuscatorSettings::default().yara_rule_names;
        assert!(!has_macros(b"plain text", &[], &names).expect("scans"));
        assert!(!has_macros(b"plain text", &["Other".to_owned()], &names).expect("scans"));
        assert!(
            has_macros(b"plain text", &["XLM_Macrosheet_NonBin".to_owned()], &names)
                .expect("scans")
        );
        let data = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../samples/ace4/office/xlm_biff8.xls"
        ))
        .expect("a sample");
        assert!(has_macros(&data, &[], &names).expect("scans"));
        assert!(matches!(
            run(
                "ace4/office/xlm_obfuscated.xlsm",
                json!({"maximum_size_mb": 0})
            ),
            Outcome::Skipped(_)
        ));
    }

    #[test]
    fn a_url_with_no_host_is_no_observable_but_still_a_detection() {
        assert!(names_a_host("https://example.com/a"));
        assert!(names_a_host("HTTP://Upper.example.com/a b"));
        assert!(names_a_host("http://[x/"));
        assert!(names_a_host("https:\\\\evil.example.com"));
        assert!(!names_a_host("http://%"));
        assert!(!names_a_host("https://.."));
    }

    #[test]
    fn the_wrappers_filter_keeps_a_modules_indented_lines() {
        let text = "Processing file: a\n\tbefore\nModule streams:\na - 1 bytes\nLine #0:\n\tLitStr 0x0001 \"x\"\n y\u{2003}\n\u{2003}yes\n\u{a0}no\n";
        assert_eq!(
            disassembly(text),
            "\tLitStr 0x0001 \"x\"\n y\u{2003}\n\u{2003}yes\n"
        );
        assert_eq!(disassembly("\tno streams\n"), "");
    }

    #[test]
    fn a_macro_document_has_its_disassembly_and_others_have_none() {
        let harness = Harness::<PCode>::new().expect("harness").dependency_result(
            "file_type",
            ace_testkit::file_type_details(
                "Composite Document File V2 Document",
                "application/msword",
            ),
        );
        let input = harness
            .sample("ace3/office/receipt_687790.doc")
            .expect("a sample");
        let outcome = harness.run_parser(input).expect("runs");
        // the fixture ace-gui's analysis view test draws (PLAN.md 5.9)
        ace_testkit::check_view_fixture("pcode_receipt_doc", &outcome);
        let Outcome::Done(result) = outcome else {
            panic!("no disassembly");
        };
        assert!(result.details.line_count > 0);
        let file = &result.files[0];
        assert_eq!(file.path.as_str(), "receipt_687790.doc.pcode.bas");
        assert!(file.redirection.is_some());
        let input = harness.sample("ace3/office/doc.docx").expect("a sample");
        assert!(matches!(
            harness.run_parser(input).expect("runs"),
            Outcome::Skipped(_)
        ));
    }

    #[test]
    fn an_office_file_by_its_extension_or_file_type_s_description() {
        let takes = PCode::takes(&());
        let check = |path: &str, description: &str| {
            let results = std::collections::BTreeMap::from([(
                "file_type".to_owned(),
                serde_json::json!({"type": description}),
            )]);
            let facts = ace_sdk::takes::Facts {
                kind: ObservableKind::File,
                directives: &[],
                relationships: &[],
                redirected: false,
                added_by: &[],
                mode: None,
                file: Some(ace_sdk::takes::FileFacts {
                    path,
                    size: Some(1),
                    mime: None,
                    yara_meta: Some(&[]),
                }),
                results: &results,
            };
            takes.check(&facts).is_ok()
        };
        // splitext's extension: leading dots aren't one, and the case is as written
        assert!(check("a.b.docm", "data"));
        assert!(!check(".docm", "data"));
        assert!(check("..x.xls", "data"));
        assert!(!check("plain", "data"));
        assert!(!check("a.DOCM", "data"));
        assert!(!check("a.docm/b", "data"));
        // or the description, lowered
        assert!(check(
            "plain",
            "Composite Document File V2 Document, Microsoft Excel"
        ));
        assert!(!check("plain", "Zip archive data"));
    }
}
