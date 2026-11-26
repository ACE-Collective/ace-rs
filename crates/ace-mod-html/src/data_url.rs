//! `html_data_url_extraction`: ace3's `HTMLDataURLAnalyzer` (`saq/modules/file_analysis/html.py`).
//!
//! Any file, whatever its type: each `data:<type>;base64,<data>` in its first `max_bytes` that
//! decodes is written to `<file>_embed_<n>.<ext>`, the extension `etc/mime.types` gives the type
//! (`bin` when it gives none), `extracted_from` the file, kept from this module and OCR, and tagged
//! `type=document.html.embedded`. `n` counts the URLs that decoded.
//!
//! Where ace-rs departs: ace3's root takes at most 500 files, which ace-rs's core doesn't, so this
//! writes at most 500 and stops there, as ace3 would when nothing else in the root had any.

use std::sync::LazyLock;

use ace_results::FileRole;
use ace_results::types::html::HtmlDataUrlAnalysis;
use ace_results::{
    AnalysisType, ObservableKind, ObservableRef, Relationship, RelationshipKind, ResultEnvelope,
};
use ace_sdk::takes::{Condition, Takes};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};
use regex::bytes::Regex;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::MAX_FILES;
use crate::py::{NAME_MAX_BYTES, mime_extension};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<HtmlDataUrlAnalyzer>();

/// `RE_HTML_EMBED`. Compiling it takes most of a task's time on a file with no data URL, and each
/// task is a process of its own, so it is compiled only for a file that `may_hold_a_data_url`.
static RE_HTML_EMBED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u)data:([^/]+/[^;]+);base64,([-A-Za-z0-9+/=]+)").expect("the pattern compiles")
});

/// Whether `RE_HTML_EMBED` can match: every match starts with `data:`.
fn may_hold_a_data_url(data: &[u8]) -> bool {
    memchr::memmem::find(data, b"data:").is_some()
}

/// Why a file with no data URL that decodes is skipped.
const NONE_DECODED: &str = "no data URL decoded";

/// ace3's OCR module, which the extracted files are kept from.
const OCR: &str = "ocr";

/// ace3's `analysis_module_html_data_url_extraction` settings.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct DataUrlSettings {
    /// How much of the file is read, in bytes.
    pub max_bytes: u64,
}

impl Default for DataUrlSettings {
    fn default() -> Self {
        DataUrlSettings {
            max_bytes: 104_857_600,
        }
    }
}

pub struct HtmlDataUrlAnalyzer;

impl Module for HtmlDataUrlAnalyzer {
    const NAME: &'static str = HtmlDataUrlAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    type Output = HtmlDataUrlAnalysis;
    type Settings = DataUrlSettings;

    fn init(_: &DataUrlSettings) -> Result<Self, ModuleError> {
        Ok(HtmlDataUrlAnalyzer)
    }

    fn takes(_: &DataUrlSettings) -> Takes {
        Takes::everything().and(Condition::not_empty(), "an empty file")
    }
}

impl Parser for HtmlDataUrlAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<DataUrlSettings>,
    ) -> Result<Outcome<HtmlDataUrlAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let limit = ctx.settings().max_bytes.min(file.size);
        let mut data = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(std::fs::File::open(&file.local_path)?, limit),
            &mut data,
        )?;
        if !may_hold_a_data_url(&data) {
            return Ok(Outcome::Skipped(NONE_DECODED.to_owned()));
        }
        let source = ObservableRef::new(ObservableKind::File, file.sha256.to_hex());
        let mut analysis: Option<HtmlDataUrlAnalysis> = None;
        let mut files = Vec::new();
        let mut count = 0usize;
        let mut raised = None;
        for found in RE_HTML_EMBED.captures_iter(&data) {
            ctx.check_cancelled()?;
            let (mime_type, encoded) = (&found[1], &found[2]);
            let Ok(decoded) = ace_pycompat::base64::b64decode_bytes(encoded) else {
                continue;
            };
            let ext = mime_extension(&String::from_utf8_lossy(mime_type));
            let name = format!("{}_embed_{count}.{ext}", file.name());
            // open() raises out of ace3's module on a name the file system can't hold, which
            // leaves the analysis as it was, and ace3's engine marks it failed with the exception
            if name.len() > NAME_MAX_BYTES {
                raised = Some(format!(
                    "OSError: [Errno 36] File name too long: '{}_embed_{count}.{ext}'",
                    file.path
                ));
                break;
            }
            // ace3's root takes no more files, and nothing more comes of this one
            if files.len() >= MAX_FILES {
                break;
            }
            let path = match file.path.as_str().rsplit_once('/') {
                Some((dir, _)) => format!("{dir}/{name}"),
                None => name,
            };
            let mut new_file = ctx.write_file(&path, &decoded, FileRole::DOCUMENT_HTML_EMBEDDED)?;
            new_file.relationships.push(Relationship::new(
                RelationshipKind::ExtractedFrom,
                source.clone(),
            ));
            new_file
                .exclude_modules
                .extend([HtmlDataUrlAnalyzer::NAME.to_owned(), OCR.to_owned()]);
            files.push(new_file);
            analysis.get_or_insert_default().count += 1;
            count += 1;
        }
        let Some(analysis) = analysis else {
            return Ok(Outcome::Skipped(NONE_DECODED.to_owned()));
        };
        let summary = (analysis.count > 0).then(|| {
            format!(
                "HTML Data URL Analysis: Extracted {} Data URLs",
                analysis.count
            )
        });
        let mut result = ResultEnvelope::new(analysis);
        result.summary = summary;
        // only an analysis that exists is marked: one that raised on its first file left none
        result.error = raised;
        result.files = files;
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pattern_finds_what_python_s_does() {
        let found: Vec<(Vec<u8>, Vec<u8>)> = RE_HTML_EMBED
            .captures_iter(b"<img src=\"data:image/png;base64,iVBO=\"> data:a\nb/c d;base64,-x_y data:x;base64,y")
            .map(|c| (c[1].to_vec(), c[2].to_vec()))
            .collect();
        assert_eq!(
            found,
            vec![
                (b"image/png".to_vec(), b"iVBO=".to_vec()),
                (b"a\nb/c d".to_vec(), b"-x".to_vec()),
            ]
        );
    }

    /// Inputs made of the pattern's own pieces, so many come close to a data URL and some are one.
    fn generated(count: usize) -> Vec<Vec<u8>> {
        const PIECES: [&[u8]; 18] = [
            b"data:",
            b"dat",
            b"a:",
            b"image",
            b"/",
            b"png",
            b";",
            b"base64,",
            b"iVBO",
            b"=",
            b"+-",
            b"\n",
            b" ",
            b"\xff\xfe",
            b"DATA:",
            b"<img src=\"",
            b"data:image/png;base64,",
            b"data:a/b;base64,",
        ];
        let mut state = 0u64;
        // splitmix64
        let mut next = move || {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        (0..count)
            .map(|_| {
                let mut input = Vec::new();
                for _ in 0..next() % 24 {
                    input.extend_from_slice(PIECES[(next() % PIECES.len() as u64) as usize]);
                }
                input
            })
            .collect()
    }

    #[test]
    fn the_pattern_matches_only_where_the_cheap_check_says_it_may() {
        let inputs = generated(20_000);
        let mut matched = 0;
        for input in &inputs {
            let found = RE_HTML_EMBED.is_match(input);
            matched += usize::from(found);
            if !may_hold_a_data_url(input) {
                assert!(!found, "{:?}", String::from_utf8_lossy(input));
            }
        }
        // the inputs reach both sides of the check
        assert!(matched > 1_000, "{matched}");
        assert!(inputs.iter().any(|i| !may_hold_a_data_url(i)));
    }
}
