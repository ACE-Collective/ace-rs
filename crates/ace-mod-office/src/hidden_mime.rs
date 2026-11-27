//! `hidden_mime`: ace3's `HiddenMIMEAnalyzer` (`saq/modules/file_analysis/mime.py`), with
//! `parse_mime` of `saq/mime_extractor.py`.
//!
//! A file that isn't an email or a packet capture is searched for a `content-type: ... boundary=`
//! line, case-insensitively. From there to the first `--<boundary>--` in the file, or to its end,
//! the bytes are parsed with Python's `BytesParser`, and each message of `walk()` whose decoded
//! payload isn't empty is written to `<file>.mime/extracted-<n>`, `n` counting the files written,
//! `extracted_from` the file.
//!
//! The parser is `ace-mod-oletools`' port of Python's feed parser, with the stock header pattern,
//! raising `RecursionError` where ace3's does.
//!
//! Where ace-rs departs: ace3's root takes at most 500 files, the file itself one of them, so this writes at most 499. ace3 names
//! each part by its path on its node, `<root>/files/<file>.mime/extracted-<n>`; this names it by its
//! path in the alert.

use ace_mod_oletools::pyemail::{self, Setup};
use ace_results::types::file_type::FileTypeAnalysis;
use ace_results::types::office::HiddenMimeAnalysis;
use ace_results::{AnalysisType, ObservableKind, ResultEnvelope};
use ace_sdk::takes::{Condition, Takes, Text, TypeFact};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};
use regex::bytes::Regex;
use std::sync::LazyLock;

use crate::{DIRECTIVE_ORIGINAL_EMAIL, MAX_FILES, dir_name_fits, extracted_from, item_list};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<HiddenMimeAnalyzer>();

/// `RE_BOUNDARY`, a bytes pattern with `re.I`: ASCII case and ASCII whitespace.
static RE_BOUNDARY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i-u)content-type\s*:.*?boundary\s*?=(\S+)").expect("a valid pattern")
});

/// Python frames under the root `_parsegen` when `parse_mime` parses, as measured in ace3's dump
/// harness at `c55f15a2`: there a part nested 970 multiparts deep parses and one 971 deep raises
/// `RecursionError`, three short of `mhtml`'s, whose parse is three frames nearer the top
/// (`docs/measurements/office-containers.md`). ace3's `5ca91195` added a frame under every module,
/// `AnalysisModule.analyze` calling `_analyze`; before it 971 parsed.
const ROOT_DEPTH: usize = 23;

pub struct HiddenMimeAnalyzer;

/// What `parse_mime` hands the parser: from the boundary's header to the end marker, or to the
/// end of the file. `None` when there is no such header.
pub fn mime_bytes(data: &[u8]) -> Option<&[u8]> {
    let found = RE_BOUNDARY.captures(data)?;
    let whole = found.get(0).expect("the match");
    let mut boundary = found.get(1).expect("a group").as_bytes();
    if boundary.starts_with(b"\"") && boundary.ends_with(b"\"") {
        boundary = if boundary.len() >= 2 {
            &boundary[1..boundary.len() - 1]
        } else {
            b""
        };
    }
    let mut end_marker = b"--".to_vec();
    end_marker.extend_from_slice(boundary);
    end_marker.extend_from_slice(b"--");
    Some(match memchr::memmem::find(data, &end_marker) {
        // a slice that ends before it starts is empty
        Some(at) => data
            .get(whole.start()..at + end_marker.len())
            .unwrap_or(&[]),
        None => &data[whole.start()..],
    })
}

/// The decoded payloads `parse_mime` writes, in order, or what Python raised parsing.
pub fn parts(data: &[u8]) -> Option<Result<Vec<Vec<u8>>, String>> {
    let mime = mime_bytes(data)?;
    Some(
        pyemail::walk_payloads(
            mime,
            Setup {
                strict_headers: true,
                root_depth: ROOT_DEPTH,
            },
        )
        .map(|parts| {
            parts
                .into_iter()
                .filter_map(|part| part.payload.filter(|p| !p.is_empty()))
                .collect()
        })
        .map_err(|e| e.to_string()),
    )
}

impl Module for HiddenMimeAnalyzer {
    const NAME: &'static str = HiddenMimeAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const DEPENDS_ON: &'static [&'static str] = &[FileTypeAnalysis::MODULE];
    type Output = HiddenMimeAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(HiddenMimeAnalyzer)
    }

    fn takes(_: &()) -> Takes {
        let file_type = FileTypeAnalysis::MODULE;
        Takes::everything()
            .and(Condition::not_empty(), "an empty file")
            .and(
                Condition::Any(vec![
                    Condition::directive(DIRECTIVE_ORIGINAL_EMAIL),
                    Condition::Name(Text::equals("email.rfc822")),
                ])
                .negated(),
                "an email",
            )
            // ace3 goes on without file_type's result
            .and(
                Condition::Any(vec![
                    Condition::result_text(file_type, "mime", Text::equals("message/rfc822")),
                    Condition::result_true(file_type, "is_email_file"),
                ])
                .negated(),
                "an email",
            )
            // ace3's `is_pcap_file`, from the file's type (PLAN.md decision 25)
            .and(
                Condition::type_fact(TypeFact::IsPcapFile).negated(),
                "a packet capture",
            )
    }
}

impl Parser for HiddenMimeAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<HiddenMimeAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let data = std::fs::read(&file.local_path)?;
        let payloads = match parts(&data) {
            None => return Ok(Outcome::Skipped("no MIME boundary".to_owned())),
            Some(Err(error)) => return Ok(Outcome::Skipped(format!("unable to parse: {error}"))),
            Some(Ok(payloads)) if payloads.is_empty() => {
                return Ok(Outcome::Skipped("no MIME parts".to_owned()));
            }
            Some(Ok(payloads)) => payloads,
        };
        // os.makedirs fails on a name the file system can't hold, which raises out of ace3's module
        if !dir_name_fits(file, ".mime") {
            return Ok(Outcome::Skipped(
                "the extraction directory's name is too long".to_owned(),
            ));
        }
        let mut analysis = HiddenMimeAnalysis::default();
        let mut files = Vec::new();
        for (index, payload) in payloads.iter().enumerate() {
            if index >= MAX_FILES {
                break;
            }
            ctx.check_cancelled()?;
            let path = format!("{}.mime/extracted-{index}", file.path);
            let mut new_file = ctx.write_file(&path, payload, None)?;
            new_file.relationships.push(extracted_from(file));
            analysis.extracted_files.push(path);
            files.push(new_file);
        }
        let summary = format!(
            "Hidden MIME Analysis: extracted {}",
            item_list(&analysis.extracted_files)
        );
        let mut result = ResultEnvelope::new(analysis);
        result.summary = Some(summary);
        result.files = files;
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mime_starts_at_the_boundary_header_and_ends_at_its_marker() {
        let data = b"junk\ncOnTeNt-TyPe : multipart/mixed; boundary=\"b\"\n\n--b\n\nx\n--b--\ntail";
        let mime = mime_bytes(data).unwrap();
        assert!(mime.starts_with(b"cOnTeNt-TyPe"));
        assert!(mime.ends_with(b"--b--"));
        assert_eq!(
            mime_bytes(b"content-type: a boundary=x\n").unwrap(),
            b"content-type: a boundary=x\n"
        );
        assert!(mime_bytes(b"content-type: a\nboundary=x").is_none());
        // the end marker before the header leaves nothing
        assert_eq!(
            mime_bytes(b"--x--\ncontent-type: a boundary=x").unwrap(),
            b""
        );
    }

    /// `nested_<n>.txt` of the dumps: multiparts nested `n` deep around one text part.
    fn nested(n: usize) -> Vec<u8> {
        let mut out = String::from("junk\nContent-Type: multipart/mixed; boundary=\"b0\"\n\n");
        for i in 0..n {
            out.push_str(&format!(
                "--b{i}\nContent-Type: multipart/mixed; boundary=\"b{}\"\n\n",
                i + 1
            ));
        }
        out.push_str(&format!("--b{n}\nContent-Type: text/plain\n\ndeep part\n"));
        for i in (0..=n).rev() {
            out.push_str(&format!("--b{i}--\n"));
        }
        out.into_bytes()
    }

    #[test]
    fn recursion_errors_come_where_ace3_s_do() {
        assert_eq!(parts(&nested(970)), Some(Ok(vec![b"deep part".to_vec()])));
        assert!(matches!(parts(&nested(971)), Some(Err(_))));
    }
}
