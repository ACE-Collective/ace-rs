//! `microsoft_script_encoding_analysis`: ace3's `MicrosoftScriptEncodingAnalyzer`
//! (`saq/modules/file_analysis/mse.py`).
//!
//! A file that starts `#@~^`, the mark of Microsoft's Script Encoder (`.vbe` and `.jse` files), is
//! tagged `microsoft_script_encoding`, sent to the sandbox, and decoded. ace3 runs a vendored Perl
//! decoder, `bin/jscript.decode.pl`, into `<file>.decrypted`, `.decrypted.vbs` for a `.vbe` or
//! `.decrypted.js` for a `.jse`, and adds that file when the decoder wrote anything, with
//! `yara_meta` type `script.encoded`. [`decode`] is that decoder: its three tables, its order of
//! tables by position, its escapes and the way its regular expressions find the block and its two
//! base64 numbers. It matches the Perl byte for byte, and where the Perl dies, with the same
//! message (`docs/measurements/scripts.md`).
//!
//! ace3 also writes the decoder's stderr to `<file>.decrypted.stderr` and never adds it, so it
//! isn't in the alert's tree; nothing here writes it. A name too long for the decoder's output or
//! that stderr file makes ace3's `open` raise after the file was tagged: the result keeps the tag
//! and directive and has no output.

use std::fs;

use ace_results::types::scripts::MicrosoftScriptEncodingAnalysis;
use ace_results::{AnalysisType, ObservableKind, ResultEnvelope, YaraMeta};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, Resources, TaskContext};

use crate::{DIRECTIVE_SANDBOX, ends_with_lower, name_fits, source};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<MicrosoftScriptEncodingAnalyzer>();

const DISPLAY_NAME: &str = "Microsoft Script Encoding Analysis";
const START: &[u8] = b"#@~^";
const END: &[u8] = b"^#~@";
/// What ace3 names the decoder's stderr, which it opens after the output.
const STDERR_SUFFIX: &str = ".decrypted.stderr";

/// Why the decoder stops without writing anything: what the Perl `die`s with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    NoStartMarker,
    NoEndMarker,
    NoLeadingChecksum,
}

impl DecodeError {
    /// The Perl's message, with its newline.
    pub fn message(self) -> &'static str {
        match self {
            DecodeError::NoStartMarker => "Start marker not found\n",
            DecodeError::NoEndMarker => "End marker not found\n",
            DecodeError::NoLeadingChecksum => "No leading checksum\n",
        }
    }
}

/// Which table decodes each of 64 positions.
#[rustfmt::skip]
const ITAB: [u8; 64] = [
    0, 2, 1, 0, 2, 1, 2, 1, 1, 2, 1, 2, 0, 1, 2, 1,
    0, 1, 2, 1, 0, 0, 2, 1, 1, 2, 0, 1, 2, 1, 1, 2,
    0, 0, 1, 2, 1, 2, 1, 0, 1, 0, 0, 2, 1, 0, 1, 2,
    0, 1, 2, 1, 0, 0, 2, 1, 1, 0, 0, 2, 1, 0, 1, 2,
];

/// What each byte below 0x80 decodes to, by table. 0xFF, from `@`, starts an escape.
#[rustfmt::skip]
const TABLES: [[u8; 128]; 3] = [
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x57, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x2E, 0x47, 0x7A, 0x56, 0x42, 0x6A, 0x2F, 0x26, 0x49, 0x41, 0x34, 0x32, 0x5B, 0x76, 0x72, 0x43,
        0x38, 0x39, 0x70, 0x45, 0x68, 0x71, 0x4F, 0x09, 0x62, 0x44, 0x23, 0x75, 0x3C, 0x7E, 0x3E, 0x5E,
        0xFF, 0x77, 0x4A, 0x61, 0x5D, 0x22, 0x4B, 0x6F, 0x4E, 0x3B, 0x4C, 0x50, 0x67, 0x2A, 0x7D, 0x74,
        0x54, 0x2B, 0x2D, 0x2C, 0x30, 0x6E, 0x6B, 0x66, 0x35, 0x25, 0x21, 0x64, 0x4D, 0x52, 0x63, 0x3F,
        0x7B, 0x78, 0x29, 0x28, 0x73, 0x59, 0x33, 0x7F, 0x6D, 0x55, 0x53, 0x7C, 0x3A, 0x5F, 0x65, 0x46,
        0x58, 0x31, 0x69, 0x6C, 0x5A, 0x48, 0x27, 0x5C, 0x3D, 0x24, 0x79, 0x37, 0x60, 0x51, 0x20, 0x36,
    ],
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x7B, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x32, 0x30, 0x21, 0x29, 0x5B, 0x38, 0x33, 0x3D, 0x58, 0x3A, 0x35, 0x65, 0x39, 0x5C, 0x56, 0x73,
        0x66, 0x4E, 0x45, 0x6B, 0x62, 0x59, 0x78, 0x5E, 0x7D, 0x4A, 0x6D, 0x71, 0x3C, 0x60, 0x3E, 0x53,
        0xFF, 0x42, 0x27, 0x48, 0x72, 0x75, 0x31, 0x37, 0x4D, 0x52, 0x22, 0x54, 0x6A, 0x47, 0x64, 0x2D,
        0x20, 0x7F, 0x2E, 0x4C, 0x5D, 0x7E, 0x6C, 0x6F, 0x79, 0x74, 0x43, 0x26, 0x76, 0x25, 0x24, 0x2B,
        0x28, 0x23, 0x41, 0x34, 0x09, 0x2A, 0x44, 0x3F, 0x77, 0x3B, 0x55, 0x69, 0x61, 0x63, 0x50, 0x67,
        0x51, 0x49, 0x4F, 0x46, 0x68, 0x7C, 0x36, 0x70, 0x6E, 0x7A, 0x2F, 0x5F, 0x4B, 0x5A, 0x2C, 0x57,
    ],
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x6E, 0x0A, 0x0B, 0x0C, 0x06, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x2D, 0x75, 0x52, 0x60, 0x71, 0x5E, 0x49, 0x5C, 0x62, 0x7D, 0x29, 0x36, 0x20, 0x7C, 0x7A, 0x7F,
        0x6B, 0x63, 0x33, 0x2B, 0x68, 0x51, 0x66, 0x76, 0x31, 0x64, 0x54, 0x43, 0x3C, 0x3A, 0x3E, 0x7E,
        0xFF, 0x45, 0x2C, 0x2A, 0x74, 0x27, 0x37, 0x44, 0x79, 0x59, 0x2F, 0x6F, 0x26, 0x72, 0x6A, 0x39,
        0x7B, 0x3F, 0x38, 0x77, 0x67, 0x53, 0x47, 0x34, 0x78, 0x5D, 0x30, 0x23, 0x5A, 0x5B, 0x6C, 0x48,
        0x55, 0x70, 0x69, 0x2E, 0x4C, 0x21, 0x24, 0x4E, 0x50, 0x09, 0x56, 0x73, 0x35, 0x61, 0x4B, 0x58,
        0x3B, 0x57, 0x22, 0x6D, 0x4D, 0x25, 0x28, 0x46, 0x4A, 0x32, 0x41, 0x3D, 0x5F, 0x4F, 0x42, 0x65,
    ],
];

/// `[A-Za-z0-9+/]{6}==`: one of the encoder's numbers, its length or its checksum.
fn is_number(bytes: &[u8]) -> bool {
    bytes.len() == 8
        && bytes[..6]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
        && &bytes[6..] == b"=="
}

/// Whether Perl takes a string as true: each step is `(m/.../ and $_ = $')`, whose value is what
/// was assigned, so an empty rest, or one that is just `0`, is as if the match failed.
fn is_true(rest: &[u8]) -> bool {
    !rest.is_empty() && rest != b"0"
}

/// `bin/jscript.decode.pl` on `data`: what it prints, or why it dies.
///
/// The Perl takes what follows the first `#@~^` up to the first `^#~@` after it, which must start
/// with a number (`^` with no `/m`), and drops a number at its end, or before a newline that ends
/// it, as `$` matches there. Each of the first three steps dies when what it leaves is empty or
/// `0`, which Perl takes as false, as if its match had failed. Each byte below 0x80 then decodes by the table its position picks; `@`
/// decodes to 0xFF, which isn't printed and makes the next byte an escape, `&#!*$` for
/// `\n\r<>@`, any other byte standing for itself. An escape counts as one position, and bytes from
/// 0x80 go through as they are and count too.
pub fn decode(data: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let rest = memchr::memmem::find(data, START)
        .map(|start| &data[start + START.len()..])
        .filter(|rest| is_true(rest))
        .ok_or(DecodeError::NoStartMarker)?;
    let block = memchr::memmem::find(rest, END)
        .map(|end| &rest[..end])
        .filter(|block| is_true(block))
        .ok_or(DecodeError::NoEndMarker)?;
    let mut body = Some(block)
        .filter(|block| block.len() >= 8 && is_number(&block[..8]))
        .map(|block| &block[8..])
        .filter(|body| is_true(body))
        .ok_or(DecodeError::NoLeadingChecksum)?;
    let n = body.len();
    if n >= 8 && is_number(&body[n - 8..]) {
        body = &body[..n - 8];
    } else if n >= 9 && body[n - 1] == b'\n' && is_number(&body[n - 9..n - 1]) {
        body = &body[..n - 9];
    }

    let mut out = Vec::with_capacity(body.len());
    let mut position = 0;
    let mut escaped = false;
    for &byte in body {
        let decoded = if escaped {
            escaped = false;
            match byte {
                b'&' => b'\n',
                b'#' => b'\r',
                b'!' => b'<',
                b'*' => b'>',
                b'$' => b'@',
                other => other,
            }
        } else if byte < 0x80 {
            let decoded = TABLES[usize::from(ITAB[position])][usize::from(byte)];
            if decoded == 0xFF {
                escaped = true;
                continue;
            }
            decoded
        } else {
            byte
        };
        out.push(decoded);
        position = (position + 1) % ITAB.len();
    }
    Ok(out)
}

pub struct MicrosoftScriptEncodingAnalyzer;

impl Module for MicrosoftScriptEncodingAnalyzer {
    const NAME: &'static str = MicrosoftScriptEncodingAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const RESOURCES: Resources = crate::RESOURCES;
    type Output = MicrosoftScriptEncodingAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(MicrosoftScriptEncodingAnalyzer)
    }
}

/// What ace3 names the decoded file: `.decrypted`, then `.vbs` for a `.vbe` and `.js` for a `.jse`.
pub fn output_suffix(path: &str) -> &'static str {
    if ends_with_lower(path, ".vbe") {
        ".decrypted.vbs"
    } else if ends_with_lower(path, ".jse") {
        ".decrypted.js"
    } else {
        ".decrypted"
    }
}

impl Parser for MicrosoftScriptEncodingAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<()>,
    ) -> Result<Outcome<MicrosoftScriptEncodingAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        if file.size == 0 {
            return Ok(Outcome::Skipped("an empty file".to_owned()));
        }
        let data = fs::read(&file.local_path)?;
        if !data.starts_with(START) {
            return Ok(Outcome::Skipped("not an encoded script".to_owned()));
        }
        let mut result = ResultEnvelope::new(MicrosoftScriptEncodingAnalysis::default());
        result.analyzed.add_tag("microsoft_script_encoding");
        result.analyzed.add_directive(DIRECTIVE_SANDBOX);

        let path = file.path.as_str();
        let suffix = output_suffix(path);
        if name_fits(file, suffix)
            && name_fits(file, STDERR_SUFFIX)
            && let Ok(decoded) = decode(&data)
            && !decoded.is_empty()
        {
            let output_path = format!("{path}{suffix}");
            let mut output = ctx.write_file(
                &output_path,
                &decoded,
                &[YaraMeta::new("type", "script.encoded").map_err(ModuleError::other)?],
            )?;
            output.redirection = Some(source(file));
            result.files.push(output);
            result.details.analysis_output = Some(output_path);
        }
        // ace3's summary prints the details' value, None when there's no output
        result.summary = Some(format!(
            "{DISPLAY_NAME}: {}",
            result.details.analysis_output.as_deref().unwrap_or("None")
        ));
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(body: &[u8]) -> Vec<u8> {
        [b"#@~^AAAAAA==".as_slice(), body, b"^#~@"].concat()
    }

    #[test]
    fn the_perl_s_errors_come_in_its_order() {
        assert_eq!(decode(b"plain"), Err(DecodeError::NoStartMarker));
        assert_eq!(decode(b"#@~^AAAAAA==x"), Err(DecodeError::NoEndMarker));
        assert_eq!(decode(b"^#~@#@~^x"), Err(DecodeError::NoEndMarker));
        assert_eq!(
            decode(b"#@~^AAAA==^#~@"),
            Err(DecodeError::NoLeadingChecksum)
        );
        assert_eq!(
            decode(b"#@~^ AAAAAA==^#~@"),
            Err(DecodeError::NoLeadingChecksum)
        );
        // what a step leaves is false to Perl when it is empty or 0
        assert_eq!(decode(b"#@~^"), Err(DecodeError::NoStartMarker));
        assert_eq!(decode(b"#@~^0"), Err(DecodeError::NoStartMarker));
        assert_eq!(decode(b"#@~^^#~@"), Err(DecodeError::NoEndMarker));
        assert_eq!(decode(b"#@~^0^#~@"), Err(DecodeError::NoEndMarker));
        assert_eq!(
            decode(b"#@~^AAAAAA==^#~@"),
            Err(DecodeError::NoLeadingChecksum)
        );
        assert_eq!(
            decode(b"#@~^AAAAAA==0^#~@"),
            Err(DecodeError::NoLeadingChecksum)
        );
        assert_eq!(decode(b"#@~^AAAAAA==00^#~@").map(|d| d.len()), Ok(2));
        // the trailing number's step doesn't die: its body may be empty
        assert_eq!(decode(b"#@~^AAAAAA==BBBBBB==^#~@"), Ok(Vec::new()));
    }

    #[test]
    fn escapes_count_one_position_and_unknown_ones_stand_for_themselves() {
        assert_eq!(decode(&block(b"@&@#@!@*@$@x")), Ok(b"\n\r<>@x".to_vec()));
        // an escape at the end prints nothing
        assert_eq!(decode(&block(b"@")), Ok(Vec::new()));
        // position 0 is table 0, where 0x7E decodes to 0x20; after one escape, position 1 is table 2
        assert_eq!(decode(&block(b"\x7e")), Ok(b" ".to_vec()));
        assert_eq!(decode(&block(b"@&\x7e")), Ok(b"\n\x42".to_vec()));
    }

    #[test]
    fn high_bytes_go_through_and_count() {
        assert_eq!(decode(&block(b"\xff\x7e")), Ok(b"\xff\x42".to_vec()));
    }

    #[test]
    fn a_trailing_number_goes_at_the_end_or_before_a_last_newline() {
        assert_eq!(decode(&block(b"BBBBBB==")), Ok(Vec::new()));
        assert_eq!(decode(&block(b"BBBBBB==\n")), Ok(Vec::new()));
        assert_eq!(decode(&block(b"BBBBBB==\n\n")).map(|d| d.len()), Ok(10));
        assert_eq!(decode(&block(b"BBBBB==")).map(|d| d.len()), Ok(7));
    }

    #[test]
    fn only_the_first_block_is_decoded() {
        let two = [block(b"\x7e"), block(b"\x7e\x7e")].concat();
        assert_eq!(decode(&two), Ok(b" ".to_vec()));
    }

    #[test]
    fn twice_encoded_output_is_decoded_again() {
        let twice = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tools/ace3/dumps/fixtures/scripts/mse/twice.vbe"),
        )
        .expect("the fixture");
        let once = decode(&twice).expect("decodes");
        assert!(once.starts_with(START));
        assert_eq!(decode(&once), Ok(b"MsgBox \"inner\"\r\n".to_vec()));
    }

    #[test]
    fn the_output_is_named_by_the_input_s_extension() {
        assert_eq!(output_suffix("a.VBE"), ".decrypted.vbs");
        assert_eq!(output_suffix("d/a.jse"), ".decrypted.js");
        assert_eq!(output_suffix("a.vbs"), ".decrypted");
    }
}
