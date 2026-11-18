//! `mhtml`: ace3's `MHTMLAnalysisModule` (`saq/modules/file_analysis/html.py`), and the MHTML
//! parse `html_js_extraction` shares with it.
//!
//! A `.mhtml` or `.mht` file, by its name alone, is parsed as MIME with Python's
//! `email.parser.BytesFeedParser`, from its first line that starts like a header, and each part
//! that isn't multipart is written to `<file>.extracted/file_<n>`, `n` counting every such part,
//! with the file's directives and `yara_meta` types and the type `document.mhtml.part`.
//!
//! The parser is `ace-mod-oletools`' port of Python's feed parser, with the stock header pattern.
//!
//! Where ace4 departs:
//!
//! - ace3's root takes at most 500 files, which ace4's core doesn't, so this writes at most 500
//!   parts.
//! - ace3 runs a pass's modules in the order of a set of their names, which Python's hash seed
//!   decides, so whether `file_type`'s `yara_meta` types are on the file when the parts copy its
//!   types changes from process to process (with the trees' seed, 0, this runs first). ace4 would
//!   decide it by which task the pool takes first, so this waits for `file_type`, and the parts
//!   always carry its types.
//! - A page Blink saves starts `From: <Saved by Blink>`, which file_type calls an email, so the
//!   email module writes the same parts too. ace4 analyzes those bytes once, under the path whose
//!   result lands first, where ace3 analyzes each path, so which module's name a script extracted
//!   from a part carries depends on which finished first.

use ace_mod_oletools::pyemail::{self, Setup, WalkedPart};
use ace_results::types::file_type::FileTypeAnalysis;
use ace_results::types::html::MhtmlAnalysis;
use ace_results::{AnalysisType, ObservableKind, ResultEnvelope, YaraMeta};
use ace_sdk::takes::{Case, Condition, Takes, Text};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};

use crate::py::NAME_MAX_BYTES;
use crate::{MAX_FILES, copied_directives, item_list};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<MhtmlAnalyzer>();

const MHTML_EXTENSIONS: [&str; 2] = [".mhtml", ".mht"];

/// Python frames under the root `_parsegen` when ace3's `mhtml` module feeds its parser, as
/// measured in ace3's dump harness: there a file nested 974 multiparts deep parses and one 975
/// deep raises `RecursionError` (`docs/measurements/html.md`).
const MHTML_ROOT_DEPTH: usize = 19;
/// The same under `html_js_extraction`'s `_parse_mhtml`, a frame deeper: 973 parse, 974 don't.
const JS_ROOT_DEPTH: usize = MHTML_ROOT_DEPTH + 1;

/// `BytesFeedParser`, the stock `headerRE`, fed from one of ace3's modules.
fn setup(root_depth: usize) -> Setup {
    Setup {
        strict_headers: true,
        root_depth,
    }
}

/// `RE_HEADER.search(line)`, `^[a-zA-Z0-9-_]+:`.
fn starts_like_a_header(line: &[u8]) -> bool {
    let name = line
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || **b == b'-' || **b == b'_')
        .count();
    name > 0 && line.get(name) == Some(&b':')
}

/// What ace3 feeds the parser: the file from its first line that starts like a header, lines
/// being split at `\n` only, as iterating a binary file splits them.
fn from_first_header(data: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < data.len() {
        if starts_like_a_header(&data[start..]) {
            return &data[start..];
        }
        match memchr::memchr(b'\n', &data[start..]) {
            Some(at) => start += at + 1,
            None => break,
        }
    }
    &[]
}

/// The parsed file's messages in `walk()` order, or what Python raised while parsing.
fn walk(data: &[u8], root_depth: usize) -> Result<Vec<WalkedPart>, String> {
    pyemail::walk_payloads(from_first_header(data), setup(root_depth)).map_err(|e| e.to_string())
}

/// `HTMLJavaScriptExtractor._parse_mhtml`: the payloads of the `text/html` and
/// `application/xhtml+xml` parts, none when the parse raises.
pub fn html_parts(data: &[u8]) -> Vec<Vec<u8>> {
    let Ok(parts) = walk(data, JS_ROOT_DEPTH) else {
        return Vec::new();
    };
    parts
        .into_iter()
        .filter(|part| {
            !part.content_type.starts_with("multipart/")
                && matches!(
                    part.content_type.as_str(),
                    "text/html" | "application/xhtml+xml"
                )
        })
        .filter_map(|part| part.payload.filter(|p| !p.is_empty()))
        .collect()
}

pub struct MhtmlAnalyzer;

impl Module for MhtmlAnalyzer {
    const NAME: &'static str = MhtmlAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const DEPENDS_ON: &'static [&'static str] = &[FileTypeAnalysis::MODULE];
    type Output = MhtmlAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(MhtmlAnalyzer)
    }

    fn takes(_: &()) -> Takes {
        // ends_with_lower: lowered as Python's str.lower
        Takes::everything().and(
            Condition::Any(
                MHTML_EXTENSIONS
                    .iter()
                    .map(|ext| Condition::Name(Text::ends_with(ext, Case::Lower)))
                    .collect(),
            ),
            "not an MHTML file",
        )
    }
}

impl Parser for MhtmlAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<MhtmlAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let data = std::fs::read(&file.local_path)?;
        let parts = match walk(&data, MHTML_ROOT_DEPTH) {
            Ok(parts) => parts,
            Err(error) => return Ok(Outcome::Skipped(format!("unable to parse: {error}"))),
        };
        // os.mkdir fails on a name the file system can't hold, which ace3 logs
        if file.name().len() + ".extracted".len() > NAME_MAX_BYTES {
            return Ok(Outcome::Skipped(
                "the extraction directory's name is too long".to_owned(),
            ));
        }
        let (directives, copied_meta) = copied_directives(ctx.observable(), file);
        let part_meta = YaraMeta::new("type", "document.mhtml.part").map_err(ModuleError::other)?;
        let mut analysis = MhtmlAnalysis::default();
        let mut files = Vec::new();
        let mut part_id = 0usize;
        for part in parts {
            if part.content_type.split('/').next() == Some("multipart") {
                continue;
            }
            let name = format!("file_{part_id}");
            part_id += 1;
            let Some(payload) = part.payload.filter(|p| !p.is_empty()) else {
                continue;
            };
            if files.len() >= MAX_FILES {
                // ace3's root takes no more files
                continue;
            }
            ctx.check_cancelled()?;
            let path = format!("{}.extracted/{name}", file.path);
            let mut new_file = ctx.write_file(&path, &payload, &[])?;
            for directive in &directives {
                new_file.add_directive(directive.clone());
            }
            new_file.yara_meta = copied_meta.clone();
            if !new_file.yara_meta.contains(&part_meta) {
                new_file.yara_meta.push(part_meta.clone());
            }
            analysis.extracted_files.push(new_file.sha256.to_hex());
            files.push(new_file);
        }
        let summary = (!analysis.extracted_files.is_empty())
            .then(|| format!("MHTML Analysis: {}", item_list(&analysis.extracted_files)));
        let mut result = ResultEnvelope::new(analysis);
        result.summary = summary;
        result.files = files;
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_before_the_headers_is_skipped() {
        assert_eq!(
            from_first_header(b"junk\n\nMIME-Version: 1.0\nx"),
            b"MIME-Version: 1.0\nx"
        );
        assert_eq!(from_first_header(b"a b: c\n:x\nX_y-1:\n"), b"X_y-1:\n");
        assert_eq!(from_first_header(b"no headers\r\n"), b"");
        assert_eq!(from_first_header(b"x\rFrom: a\n"), b"");
    }

    /// `depth.py`'s file: multiparts nested `n` deep around one HTML part.
    fn nested(n: usize) -> Vec<u8> {
        let mut out =
            String::from("MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"b0\"\n\n");
        for i in 0..n {
            out.push_str(&format!(
                "--b{i}\nContent-Type: multipart/mixed; boundary=\"b{}\"\n\n",
                i + 1
            ));
        }
        out.push_str(&format!(
            "--b{n}\nContent-Type: text/html\n\n<script>alert('deep part')</script>\n"
        ));
        for i in (0..=n).rev() {
            out.push_str(&format!("--b{i}--\n"));
        }
        out.into_bytes()
    }

    #[test]
    fn recursion_errors_come_where_ace3_s_do() {
        assert!(walk(&nested(974), MHTML_ROOT_DEPTH).is_ok());
        assert!(walk(&nested(975), MHTML_ROOT_DEPTH).is_err());
        assert_eq!(html_parts(&nested(973)).len(), 1);
        assert!(html_parts(&nested(974)).is_empty());
    }

    #[test]
    fn html_parts_are_the_html_and_xhtml_ones() {
        let mht = b"MIME-Version: 1.0\nContent-Type: multipart/related; boundary=\"b\"\n\n--b\nContent-Type: text/html\nContent-Transfer-Encoding: quoted-printable\n\n<p>a=3Db</p>\n--b\nContent-Type: image/png\n\nPNG\n--b\nContent-Type: application/xhtml+xml\n\n<html/>\n--b--\n";
        let parts = html_parts(mht);
        assert_eq!(parts, vec![b"<p>a=b</p>".to_vec(), b"<html/>".to_vec()]);
    }
}
