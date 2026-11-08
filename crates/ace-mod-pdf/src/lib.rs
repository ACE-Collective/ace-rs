//! The PDF module, a port of ace3's `PDFAnalyzer` (`saq/modules/file_analysis/pdf.py`) that replaces
//! its pikepdf and `pdf-parser.py` with libqpdf and a Rust port of the script, in the task's own
//! process (PLAN.md 4.9, decision 6).
//!
//! For a file with `%PDF-` in its first 1024 bytes it writes:
//!
//! - `<file>.pdfparser`, the script's dump of the objects (`type=document.pdf.object`);
//! - when the file is encrypted and opens with the empty password, a copy without the encryption at
//!   `<name>.decrypted.pdf` (`type=document.pdf`, tagged `decrypted_pdf`) and its own `.pdfparser`,
//!   and the encryption's parameters in the details;
//! - `<file>.annotation_uris.txt`, the URIs of the annotations' actions
//!   (`type=document.pdf.annotation_uris`);
//! - `<file>.field_<name>_decoded.bin`, a form field whose value is a long base64 name, decoded
//!   (`type=document.pdf.form_field`);
//! - `<file>.js_<name>.js`, a script of the document's JavaScript name tree
//!   (`type=script.javascript`).
//!
//! ace3 also runs Ghostscript here and scans its rewritten PDF. A contained task can't start a
//! process, so that's left out (`tools/ace3/trees/differences.md`, and PLAN.md 7.3).

pub mod objects;
pub mod pdfparser;
pub mod qpdf;

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use ace_results::types::pdf::PdfAnalysis;
use ace_results::{
    NewFile, ObservableKind, ObservableRef, Relationship, RelationshipKind, ResultEnvelope,
    YaraMeta,
};
use ace_sdk::{InputFile, Manifest, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::objects::{Objects, Py};
use crate::pdfparser::{Limits, Run};
use crate::qpdf::{Document, Kind};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<PdfAnalyzer>();

const EXTRACT_URLS: &str = "extract_urls";
/// ace3's modules that mustn't read the decrypted copy, by their names in `saq.default.yaml`, as
/// well as this one.
const NOT_ON_THE_COPY: &[&str] = &["pdftotext", "exif", "qrcode"];
/// A file name's limit, which ace3 meets on its filesystem. Past it a write raises, and ace3 catches
/// that as it would anything else in the same block.
const NAME_MAX: usize = 255;

/// The module has no settings. ace3's only one is where the script is.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PdfSettings {}

/// The PDF module.
pub struct PdfAnalyzer;

impl Module for PdfAnalyzer {
    const NAME: &'static str = "pdf_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    // ace3's global maximum_analysis_time, in which it gives each tool 10 s. libqpdf runs here with
    // nothing to stop it but the supervisor's deadline. Memory: `docs/measurements/pdf-hostile.md`.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        memory_mb: 2048,
        cpu_seconds: 60,
    };
    type Output = PdfAnalysis;
    type Settings = PdfSettings;

    fn init(_: &PdfSettings) -> Result<Self, ModuleError> {
        Ok(PdfAnalyzer)
    }
}

/// `%PDF-` anywhere in the first 1024 bytes, as ace3 tests it.
fn looks_like_pdf(local_path: &Path) -> std::io::Result<bool> {
    let mut head = Vec::with_capacity(1024);
    File::open(local_path)?.take(1024).read_to_end(&mut head)?;
    Ok(head.windows(5).any(|w| w == b"%PDF-"))
}

fn yara_meta(kind: &str) -> Result<Vec<YaraMeta>, ModuleError> {
    Ok(vec![
        YaraMeta::new("type", kind).map_err(ModuleError::other)?,
    ])
}

/// `re.sub(r'[^A-Za-z0-9_-]', '_', name)`.
fn safe_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// `base64.b64decode` in its default form, which is `binascii.a2b_base64` with `strict_mode` off,
/// for text of the alphabet and `=` alone. None for what it raises on.
fn b64decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut position = 0;
    let mut pads = 0;
    let mut left = 0u8;
    for byte in text.bytes() {
        if byte == b'=' {
            pads += 1;
            if position >= 2 && position + pads >= 4 {
                return Some(out);
            }
            continue;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        pads = 0;
        match position {
            0 => {
                position = 1;
                left = value;
            }
            1 => {
                position = 2;
                out.push((left << 2) | (value >> 4));
                left = value & 0x0F;
            }
            2 => {
                position = 3;
                out.push((left << 4) | (value >> 2));
                left = value & 0x03;
            }
            _ => {
                position = 0;
                out.push((left << 6) | value);
                left = 0;
            }
        }
    }
    (position == 0).then_some(out)
}

/// A base64 form field's bytes, by ace3's rules: a name of at least 64 characters of the alphabet,
/// which decodes to at least 32 bytes. pikepdf's `str(Name)` keeps the slash, which goes first.
pub fn field_payload(name: &str) -> Option<Vec<u8>> {
    let candidate = name.trim_start_matches('/');
    if candidate.chars().count() < 64 {
        return None;
    }
    if !candidate
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    {
        return None;
    }
    b64decode(candidate).filter(|decoded| decoded.len() >= 32)
}

/// `str.strip()` leaves nothing.
fn is_blank(text: &str) -> bool {
    text.chars()
        .all(|c| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// The script's run on a file. `path` is the name it would see, whose ending decides whether it's a
/// zip, and `alert_path` what's printed if that fails, as ace3's would name its own node's path.
fn run_pdfparser(local_path: &Path, name: &str, limits: &Limits) -> std::io::Result<Run> {
    let data = std::fs::read(local_path)?;
    Ok(run_pdfparser_on(&data, name, limits))
}

/// As `run_pdfparser`, on bytes.
pub fn run_pdfparser_on(data: &[u8], name: &str, limits: &Limits) -> Run {
    if name.to_lowercase().ends_with(".zip") {
        return match pdfparser::first_zip_member(data, limits) {
            Ok(member) => pdfparser::run(&member, limits),
            Err(message) => pdfparser::failed_zip(name, &message),
        };
    }
    pdfparser::run(data, limits)
}

struct Output<'a> {
    ctx: &'a TaskContext<PdfSettings>,
    file_ref: ObservableRef,
    result: ResultEnvelope<PdfAnalysis>,
}

impl Output<'_> {
    /// `add_file_observable` as ace3's blocks use it: `extracted_from`, `extract_urls`, redirected
    /// to the PDF and not for this module.
    fn add(
        &mut self,
        path: &str,
        bytes: &[u8],
        kind: &str,
        source: &ObservableRef,
    ) -> Result<(), ModuleError> {
        let mut file = self.write(path, bytes, kind, source)?;
        file.add_directive(EXTRACT_URLS);
        file.exclude_modules.push(PdfAnalyzer::NAME.to_owned());
        self.result.files.push(file);
        Ok(())
    }

    fn write(
        &self,
        path: &str,
        bytes: &[u8],
        kind: &str,
        source: &ObservableRef,
    ) -> Result<NewFile, ModuleError> {
        let mut file = self.ctx.write_file(path, bytes, &yara_meta(kind)?)?;
        file.relationships.push(Relationship::new(
            RelationshipKind::ExtractedFrom,
            source.clone(),
        ));
        file.redirection = Some(self.file_ref.clone());
        Ok(file)
    }

    /// `run_pdfparser`: the dump, with no directive but `extract_urls` and no exclusion, because the
    /// module tells its own output by the name.
    fn add_pdfparser(
        &mut self,
        path: &str,
        run: &Run,
        source: &ObservableRef,
    ) -> Result<(), ModuleError> {
        if let Some(stop) = &run.stopped {
            tracing::warn!(?stop, "pdf-parser stopped early");
        }
        let mut file = self.write(path, &run.stdout, "document.pdf.object", source)?;
        file.add_directive(EXTRACT_URLS);
        self.result.files.push(file);
        Ok(())
    }
}

fn name_fits(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|name| name.len() <= NAME_MAX)
}

/// Where a file named from analyzed content goes, ace3's `create_output_file`: the files directory
/// itself, and a name taken gets a number.
fn output_name(name: &str, taken: &[NewFile]) -> String {
    let free = |candidate: &str| !taken.iter().any(|f| f.path.as_str() == candidate);
    if free(name) {
        return name.to_owned();
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, format!(".{ext}")),
        _ => (name, String::new()),
    };
    let mut number = 1;
    loop {
        let candidate = format!("{stem}_{number:03}{ext}");
        if free(&candidate) {
            return candidate;
        }
        number += 1;
    }
}

impl Parser for PdfAnalyzer {
    fn analyze(&self, ctx: &TaskContext<PdfSettings>) -> Result<Outcome<PdfAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let path = file.path.as_str();
        if path.ends_with(".pdfparser") {
            return Ok(Outcome::Skipped("this module's own output".to_owned()));
        }
        if path.ends_with(".ocr") {
            return Ok(Outcome::Skipped("OCR output".to_owned()));
        }
        if !looks_like_pdf(&file.local_path)? {
            return Ok(Outcome::Skipped("not a PDF".to_owned()));
        }
        let mut output = Output {
            ctx,
            file_ref: ObservableRef::new(ObservableKind::File, file.sha256.to_hex()),
            result: ResultEnvelope::new(PdfAnalysis::default()),
        };
        let limits = Limits::TASK;
        let run = run_pdfparser(&file.local_path, path, &limits)?;
        let source = output.file_ref.clone();
        output.add_pdfparser(&format!("{path}.pdfparser"), &run, &source)?;
        drop(run);
        ctx.check_cancelled()?;

        match Document::open(&file.local_path) {
            Ok(document) => read_document(&document, file, &mut output, &limits)?,
            // ace3 logs this and leaves the file with what pdf-parser made. An encrypted file that
            // needs a password is PDFEncryptionAnalyzer's, in ace3 and in 7.x here.
            Err(raised) => tracing::warn!(%raised, "libqpdf can't open the file"),
        }
        Ok(Outcome::Done(output.result))
    }
}

fn read_document(
    document: &Document,
    file: &InputFile,
    output: &mut Output<'_>,
    limits: &Limits,
) -> Result<(), ModuleError> {
    let path = file.path.as_str().to_owned();
    let objects = Objects { document };
    if document.is_encrypted() && !save_decrypted_copy(&objects, file, output, limits)? {
        return Ok(());
    }
    output.ctx.check_cancelled()?;

    let uris_path = format!("{path}.annotation_uris.txt");
    match annotation_text(&objects) {
        Ok(Some(text)) if name_fits(&uris_path) => {
            let source = output.file_ref.clone();
            output.add(
                &uris_path,
                text.as_bytes(),
                "document.pdf.annotation_uris",
                &source,
            )?;
        }
        Ok(_) => {}
        Err(raised) => tracing::warn!(%raised, "annotation extraction failed"),
    }

    if let Err(raised) = add_form_fields(&objects, &path, output)? {
        tracing::warn!(%raised, "form field extraction failed");
    }
    if let Err(raised) = add_javascript(&objects, &path, output)? {
        tracing::warn!(%raised, "JavaScript extraction failed");
    }
    Ok(())
}

fn annotation_text(objects: &Objects<'_>) -> Result<Option<String>, qpdf::Raised> {
    let uris = objects.annotation_uris()?;
    let mut lines = Vec::with_capacity(uris.len());
    for uri in &uris {
        lines.push(objects.text(uri)?);
    }
    Ok((!lines.is_empty()).then(|| lines.join("\n")))
}

/// ace3's form field block. The outer error is the task's and the inner one is what its `except`
/// catches.
fn add_form_fields(
    objects: &Objects<'_>,
    path: &str,
    output: &mut Output<'_>,
) -> Result<Result<(), qpdf::Raised>, ModuleError> {
    let source = output.file_ref.clone();
    let fields = match objects.form_fields() {
        Ok(fields) => fields,
        Err(raised) => return Ok(Err(raised)),
    };
    for field in &fields {
        let name = match objects
            .field_name(field)
            .and_then(|name| objects.text(&name))
        {
            Ok(name) => safe_name(&name),
            Err(raised) => return Ok(Err(raised)),
        };
        let value = match objects.get(field, "/V") {
            Ok(value) => value,
            Err(raised) => return Ok(Err(raised)),
        };
        let Py::Object(handle) = value else { continue };
        match objects.document.kind(handle) {
            Ok(Kind::Name) => {}
            Ok(_) => continue,
            Err(raised) => return Ok(Err(raised)),
        }
        let text = match objects.text(&Py::Object(handle)) {
            Ok(text) => text,
            Err(raised) => return Ok(Err(raised)),
        };
        let Some(decoded) = field_payload(&text) else {
            continue;
        };
        let target = format!("{path}.field_{name}_decoded.bin");
        if !name_fits(&target) {
            return Ok(Err(qpdf::Raised::new("OSError", "File name too long")));
        }
        output.add(&target, &decoded, "document.pdf.form_field", &source)?;
    }
    Ok(Ok(()))
}

/// ace3's JavaScript block, with the same two levels of error as `add_form_fields`.
fn add_javascript(
    objects: &Objects<'_>,
    path: &str,
    output: &mut Output<'_>,
) -> Result<Result<(), qpdf::Raised>, ModuleError> {
    let source = output.file_ref.clone();
    let pairs = match objects.javascript() {
        Ok(pairs) => pairs,
        Err(raised) => return Ok(Err(raised)),
    };
    for (name, action) in &pairs {
        let name = match objects.text(name) {
            Ok(name) => safe_name(&name),
            Err(raised) => return Ok(Err(raised)),
        };
        let script = match objects.get(action, "/JS") {
            Ok(script) => script,
            Err(raised) => return Ok(Err(raised)),
        };
        if matches!(script, Py::None) {
            continue;
        }
        let content = match script_text(objects, &script) {
            Ok(content) => content,
            Err(raised) => return Ok(Err(raised)),
        };
        if is_blank(&content) {
            continue;
        }
        let target = format!("{path}.js_{name}.js");
        if !name_fits(&target) {
            return Ok(Err(qpdf::Raised::new("OSError", "File name too long")));
        }
        output.add(&target, content.as_bytes(), "script.javascript", &source)?;
    }
    Ok(Ok(()))
}

/// `js_value.read_bytes().decode('utf-8', errors='replace')` of a stream, `str(js_value)` of anything
/// else.
fn script_text(objects: &Objects<'_>, script: &Py) -> Result<String, qpdf::Raised> {
    if let Py::Object(handle) = script
        && objects.document.kind(*handle)? == Kind::Stream
    {
        let data = objects.document.stream_data(*handle)?;
        // ace3 writes whatever it decodes. A few KB can decode to gigabytes, and this would go
        // to the bucket, so it ends the block as a failure to read would
        if data.len() > Limits::TASK.output_bytes {
            return Err(qpdf::Raised::new(
                "MemoryError",
                "a script past the output limit",
            ));
        }
        return Ok(String::from_utf8_lossy(&data).into_owned());
    }
    objects.text(script)
}

/// `save_decrypted_copy`: the encryption's parameters, the tag, the copy, and the copy's dump. A
/// failure to write the copy is caught and logged in ace3, and the parameters and tag stay. It
/// returns false for a failure to read the parameters, which in ace3 reaches the outer `except` and
/// ends the module's work on the file.
fn save_decrypted_copy(
    objects: &Objects<'_>,
    file: &InputFile,
    output: &mut Output<'_>,
    limits: &Limits,
) -> Result<bool, ModuleError> {
    let encryption = match objects.encryption(&file.local_path) {
        Ok(encryption) => encryption,
        Err(raised) => {
            tracing::warn!(%raised, "reading the encryption failed");
            return Ok(false);
        }
    };
    output.result.summary = Some(format!(
        "PDF Analysis: encrypted ({} {}-bit, R{}, P {}), opens with an empty user password",
        encryption.method, encryption.bits, encryption.r, encryption.p
    ));
    output.result.details.encryption = Some(encryption);
    output
        .result
        .analyzed
        .add_tag("encrypted_pdf_empty_password");

    let saved = objects
        .fix_page_tree_counts()
        .and_then(|()| objects.document.save_decrypted());
    let copy = match saved {
        Ok(copy) => copy,
        Err(raised) => {
            tracing::warn!(%raised, "can't save a decrypted copy");
            return Ok(true);
        }
    };
    let name = output_name(
        &format!("{}.decrypted.pdf", file.name()),
        &output.result.files,
    );
    let source = output.file_ref.clone();
    let mut decrypted = output.write(&name, &copy, "document.pdf", &source)?;
    decrypted.add_tag("decrypted_pdf");
    decrypted.exclude_modules.push(PdfAnalyzer::NAME.to_owned());
    for module in NOT_ON_THE_COPY {
        decrypted.exclude_modules.push((*module).to_owned());
    }
    let copy_ref = decrypted.reference();
    let copy_name = decrypted.path.as_str().to_owned();
    output.result.files.push(decrypted);
    let run = pdfparser::run(&copy, limits);
    drop(copy);
    let dump = output_name(&format!("{copy_name}.pdfparser"), &output.result.files);
    output.add_pdfparser(&dump, &run, &copy_ref)?;
    Ok(true)
}

/// Where a side of `tools/library-diff/run` starts, in the module's crate so the binaries stay thin.
pub mod side {
    use serde_json::{Value, json};

    /// Prints a side's one line.
    pub fn answer(reply: &Value) {
        println!("{reply}");
    }

    /// The contract's `{"error": ...}`.
    pub fn error(kind: &str, message: &str) -> Value {
        json!({"error": {"type": kind, "message": message}})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_become_file_names_as_ace3_makes_them() {
        assert_eq!(safe_name("a b/c-d_é"), "a_b_c-d__");
    }

    #[test]
    fn a_field_needs_a_long_base64_name() {
        let long = "QUJD".repeat(16);
        assert_eq!(field_payload(&format!("/{long}")), Some(b"ABC".repeat(16)));
        assert_eq!(field_payload("/short"), None);
        assert_eq!(field_payload(&format!("/{}!", "A".repeat(70))), None);
        // decodes, but to too little
        assert_eq!(field_payload(&format!("QQ=={}", "=".repeat(70))), None);
        // one data character past a group is an error in binascii
        assert_eq!(field_payload(&"A".repeat(65)), None);
    }

    #[test]
    fn b64decode_stops_at_padding_as_binascii_does() {
        assert_eq!(b64decode("QUJD").as_deref(), Some(&b"ABC"[..]));
        assert_eq!(b64decode("QUI=QUJD").as_deref(), Some(&b"AB"[..]));
        assert_eq!(b64decode("QQ==").as_deref(), Some(&b"A"[..]));
        assert_eq!(b64decode("QQ"), None);
        assert_eq!(b64decode("Q"), None);
    }

    #[test]
    fn a_taken_output_name_gets_a_number() {
        let digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .expect("a digest");
        let taken = vec![NewFile::new(
            "a.decrypted.pdf".parse().expect("a path"),
            digest,
            0,
        )];
        assert_eq!(output_name("b.pdf", &taken), "b.pdf");
        assert_eq!(
            output_name("a.decrypted.pdf", &taken),
            "a.decrypted_001.pdf"
        );
    }

    mod on_samples {
        use ace_results::ObservableKind;
        use ace_sdk::Outcome;
        use ace_testkit::Harness;

        use super::super::*;

        /// What the module writes for a sample: name, yara_meta type and the file's record.
        fn run(sample: &str) -> Option<ResultEnvelope<PdfAnalysis>> {
            let harness = Harness::<PdfAnalyzer>::new().expect("harness");
            let input = harness.sample(sample).expect("a sample");
            match harness.run_parser(input).expect("runs") {
                Outcome::Done(result) => Some(result),
                Outcome::Skipped(_) => None,
                Outcome::Delay(_) => panic!("a delay"),
            }
        }

        fn names(result: &ResultEnvelope<PdfAnalysis>) -> Vec<&str> {
            result.files.iter().map(|f| f.path.as_str()).collect()
        }

        #[test]
        fn only_a_file_with_the_header_in_its_first_1024_bytes_is_analyzed() {
            assert!(run("ace4/pdf/name_only_pdf_not_a_pdf.pdf").is_none());
            assert!(run("ace4/pdf/header_at_1024.pdf").is_none());
            assert!(run("ace4/pdf/header_at_1000.pdf").is_some());
        }

        #[test]
        fn a_file_libqpdf_refuses_keeps_its_dump() {
            for sample in [
                "ace4/pdf/broken_no_root.pdf",
                "ace4/pdf/encrypted_needs_password_aes_256.pdf",
            ] {
                let result = run(sample).expect("a result");
                assert_eq!(result.files.len(), 1, "{sample}");
                assert!(result.files[0].path.as_str().ends_with(".pdfparser"));
                assert!(result.details.encryption.is_none());
                assert!(result.summary.is_none());
            }
        }

        #[test]
        fn a_plain_pdf_with_uris_gets_their_file() {
            let result = run("ace4/pdf/uris.pdf").expect("a result");
            assert_eq!(
                names(&result),
                ["uris.pdf.pdfparser", "uris.pdf.annotation_uris.txt"]
            );
            assert!(result.details.encryption.is_none());
            let dump = &result.files[0];
            assert_eq!(dump.yara_meta[0].as_str(), "type=document.pdf.object");
            assert_eq!(dump.directives, [EXTRACT_URLS]);
            assert!(dump.exclude_modules.is_empty());
            let uris = &result.files[1];
            assert_eq!(
                uris.yara_meta[0].as_str(),
                "type=document.pdf.annotation_uris"
            );
            assert_eq!(uris.directives, [EXTRACT_URLS]);
            assert_eq!(uris.exclude_modules, ["pdf_analyzer"]);
            let redirection = uris.redirection.as_ref().expect("a redirection");
            assert_eq!(redirection.kind, ObservableKind::File);
        }

        #[test]
        fn form_fields_and_scripts_are_filtered_as_ace3_does() {
            let form = run("ace4/pdf/form_fields.pdf").expect("a result");
            assert_eq!(
                names(&form),
                [
                    "form_fields.pdf.pdfparser",
                    "form_fields.pdf.field_payload_one_decoded.bin",
                    "form_fields.pdf.field_utf8-___name_decoded.bin",
                    "form_fields.pdf.field_unknown_decoded.bin",
                    "form_fields.pdf.field_indirect_field_decoded.bin",
                ]
            );
            let script = run("ace4/pdf/javascript.pdf").expect("a result");
            assert_eq!(
                names(&script),
                [
                    "javascript.pdf.pdfparser",
                    "javascript.pdf.js_literal.js",
                    "javascript.pdf.js_name_with__spaces_.js",
                    "javascript.pdf.js_u.js",
                    "javascript.pdf.js_utf16.js",
                    "javascript.pdf.js_not_utf8.js",
                    "javascript.pdf.js_number.js",
                ]
            );
            assert_eq!(
                script.files[1].yara_meta[0].as_str(),
                "type=script.javascript"
            );
        }

        #[test]
        fn an_exception_keeps_what_each_block_had_before_it() {
            // the URI list goes whole, because the file is written after the loop
            let lost = run("ace4/pdf/annot_items.pdf").expect("a result");
            assert_eq!(names(&lost), ["annot_items.pdf.pdfparser"]);
            // a field is written as it's read
            let kept = run("ace4/pdf/field_items.pdf").expect("a result");
            assert_eq!(
                names(&kept),
                [
                    "field_items.pdf.pdfparser",
                    "field_items.pdf.field_kept_decoded.bin"
                ]
            );
        }

        #[test]
        fn an_encrypted_pdf_gets_its_parameters_a_copy_and_the_copys_dump() {
            for (sample, method, bits, r) in [
                ("encrypted_rc4_40.pdf", "rc4", 40, 2),
                ("encrypted_rc4_128.pdf", "rc4", 128, 3),
                ("encrypted_rc4_crypt_filter.pdf", "rc4", 128, 4),
                ("encrypted_aes_128.pdf", "aes", 128, 4),
                ("encrypted_aes_256_r5.pdf", "aesv3", 256, 5),
                ("encrypted_aes_256_r6.pdf", "aesv3", 256, 6),
                ("encrypted_identity_streams.pdf", "none", 128, 4),
            ] {
                let result = run(&format!("ace4/pdf/{sample}")).expect("a result");
                if sample == "encrypted_aes_128.pdf" {
                    // the fixture ace-gui's analysis view test draws (PLAN.md 5.9)
                    ace_testkit::check_view_fixture(
                        "pdf_encrypted_aes_128",
                        &Outcome::Done(result.clone()),
                    );
                }
                let encryption = result.details.encryption.clone().expect("its encryption");
                assert_eq!(
                    (encryption.method.as_str(), encryption.bits, encryption.r),
                    (method, bits, r),
                    "{sample}"
                );
                assert_eq!(encryption.filter, "/Standard");
                assert!(!encryption.owner_password_empty);
                assert_eq!(
                    result.summary.as_deref(),
                    Some(
                        format!(
                            "PDF Analysis: encrypted ({method} {bits}-bit, R{r}, P {}), opens with an empty user password",
                            encryption.p
                        )
                        .as_str()
                    )
                );
                assert_eq!(result.analyzed.tags, ["encrypted_pdf_empty_password"]);
                let copy = &result.files[1];
                assert_eq!(copy.path.as_str(), format!("{sample}.decrypted.pdf"));
                assert_eq!(copy.tags, ["decrypted_pdf"]);
                assert_eq!(copy.yara_meta[0].as_str(), "type=document.pdf");
                assert!(copy.directives.is_empty());
                assert_eq!(
                    copy.exclude_modules,
                    ["pdf_analyzer", "pdftotext", "exif", "qrcode"]
                );
                let dump = &result.files[2];
                assert_eq!(
                    dump.path.as_str(),
                    format!("{sample}.decrypted.pdf.pdfparser")
                );
                assert_eq!(dump.relationships[0].target, copy.reference());
                assert_eq!(dump.redirection, copy.redirection);
                // the dump, the copy and its dump, the URIs, a field and two scripts. With a stream
                // method of none, the script in a stream doesn't decode
                let expected = if method == "none" { 6 } else { 7 };
                assert_eq!(result.files.len(), expected, "{:?}", names(&result));
            }
            let both = run("ace4/pdf/encrypted_owner_also_empty.pdf").expect("a result");
            assert!(
                both.details
                    .encryption
                    .expect("its encryption")
                    .owner_password_empty
            );
            let none = run("ace4/pdf/encrypted_no_permissions.pdf").expect("a result");
            let permissions = none.details.encryption.expect("its encryption").permissions;
            assert!(!permissions.extract && !permissions.print_lowres && !permissions.modify_other);
        }
    }
}
