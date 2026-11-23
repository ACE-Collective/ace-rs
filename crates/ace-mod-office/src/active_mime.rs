//! `active_mime`: ace3's `ActiveMimeAnalyzer` (`saq/modules/file_analysis/mime.py`), with
//! `parse_active_mime` of `saq/mime_extractor.py`.
//!
//! A file that starts `ActiveMime` has its header's fields walked and the rest inflated with
//! `zlib.decompress` into `<file>.activemime`, tagged `activemime`, `extracted_from` the file and
//! typed `document.activemime`. A header that runs past the file's end, a tail type field that isn't
//! four bytes, or a stream zlib refuses leaves no result, as ace3 logs it and creates none.
//!
//! Where ace-rs departs: ace3 inflates into memory with no limit, so a bomb grows until Python raises
//! `MemoryError` and the module fails. Here the payload stops at 256 MiB, as `olevba`'s ActiveMime
//! does (`ace-mod-oletools`), and a larger one leaves no result. ace3 names the payload by its path
//! on its node, `<root>/files/<file>.activemime`; this names it by its path in the alert.

use ace_mod_oletools::pyzip::zlib_decompress;
use ace_results::FileRole;
use ace_results::types::office::ActiveMimeAnalysis;
use ace_results::{AnalysisType, ObservableKind, ResultEnvelope};
use ace_sdk::takes::{Condition, Takes};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};

use crate::extracted_from;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<ActiveMimeAnalyzer>();

/// The most a payload may inflate to.
const MAX_PAYLOAD: usize = 256 * 1024 * 1024;

pub struct ActiveMimeAnalyzer;

/// `_MalformedActiveMime`, or zlib's error inside it.
#[derive(Debug, PartialEq, Eq)]
pub enum Malformed {
    /// A field ran past the end, or wasn't the size it must be: the offset and why.
    Field(usize, String),
    /// `zlib.decompress` raised, or the payload passed `MAX_PAYLOAD`.
    Payload(String),
}

/// `parse_active_mime`: the payload, `None` for a file that doesn't start `ActiveMime`.
pub fn parse_active_mime(rawdoc: &[u8]) -> Option<Result<Vec<u8>, Malformed>> {
    if !rawdoc[..rawdoc.len().min(12)].starts_with(b"ActiveMime") {
        return None;
    }
    Some(parse(rawdoc))
}

fn read_u32(rawdoc: &[u8], cursor: usize) -> Result<u32, Malformed> {
    match rawdoc.get(cursor..cursor.saturating_add(4)) {
        Some(b) if b.len() == 4 => Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        _ => Err(Malformed::Field(
            cursor,
            format!("truncated reading uint32 (buffer size {})", rawdoc.len()),
        )),
    }
}

fn skip(rawdoc: &[u8], cursor: usize, length: usize) -> Result<usize, Malformed> {
    if cursor + length > rawdoc.len() {
        return Err(Malformed::Field(
            cursor,
            format!(
                "field of size {length} exceeds buffer size {}",
                rawdoc.len()
            ),
        ));
    }
    Ok(cursor + length)
}

fn parse(rawdoc: &[u8]) -> Result<Vec<u8>, Malformed> {
    // should be 01f0
    let mut cursor = skip(rawdoc, 12, 2)?;
    let field_size = read_u32(rawdoc, cursor)? as usize;
    cursor += 4;
    // should be ffffffff
    cursor = skip(rawdoc, cursor, field_size)?;
    // should be {x}0000{y}f0
    cursor = skip(rawdoc, cursor, 4)?;
    let _compressed_size = read_u32(rawdoc, cursor)?;
    cursor += 4;
    let field_size_d = read_u32(rawdoc, cursor)? as usize;
    cursor += 4;
    let field_size_e = read_u32(rawdoc, cursor)? as usize;
    cursor += 4;
    // should be 00000000 or 00000000 00000001
    cursor = skip(rawdoc, cursor, field_size_d)?;
    // the vba tail type is read as a uint32, so its field must be exactly 4 bytes
    if field_size_e != 4 {
        return Err(Malformed::Field(
            cursor,
            format!("unexpected vba tail type field size {field_size_e}"),
        ));
    }
    let _vba_tail_type = read_u32(rawdoc, cursor)?;
    cursor += field_size_e;
    let _size = read_u32(rawdoc, cursor)?;
    cursor += 4;
    zlib_decompress(&rawdoc[cursor..], true, MAX_PAYLOAD)
        .map_err(|e| Malformed::Payload(e.to_string()))
}

impl Module for ActiveMimeAnalyzer {
    const NAME: &'static str = ActiveMimeAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    type Output = ActiveMimeAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(ActiveMimeAnalyzer)
    }

    fn takes(_: &()) -> Takes {
        Takes::everything().and(Condition::not_empty(), "an empty file")
    }
}

impl Parser for ActiveMimeAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<ActiveMimeAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let rawdoc = std::fs::read(&file.local_path)?;
        let payload = match parse_active_mime(&rawdoc) {
            None => return Ok(Outcome::Skipped("not an ActiveMime file".to_owned())),
            Some(Err(why)) => {
                return Ok(Outcome::Skipped(format!(
                    "a malformed ActiveMime document: {why:?}"
                )));
            }
            Some(Ok(payload)) => payload,
        };
        let path = format!("{}.activemime", file.path);
        let mut new_file = ctx.write_file(&path, &payload, FileRole::DOCUMENT_ACTIVEMIME)?;
        new_file.add_tag("activemime");
        new_file.relationships.push(extracted_from(file));
        let mut result = ResultEnvelope::new(ActiveMimeAnalysis {
            extracted_file: path.clone(),
        });
        result.summary = Some(format!("Active MIME Analysis: extracted {path}"));
        result.files.push(new_file);
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn activemime(payload: &[u8], field_e: u32, compressed: Option<Vec<u8>>) -> Vec<u8> {
        use std::io::Write;
        let body = compressed.unwrap_or_else(|| {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(payload).unwrap();
            e.finish().unwrap()
        });
        let mut out = b"ActiveMime\0\0\x01\xf0".to_vec();
        out.extend(4u32.to_le_bytes());
        out.extend([0xff; 4]);
        out.extend(b"\x01\x00\x00\xf0");
        out.extend((body.len() as u32).to_le_bytes());
        out.extend(4u32.to_le_bytes());
        out.extend(field_e.to_le_bytes());
        out.extend([0; 4]);
        out.extend(1u32.to_le_bytes());
        out.extend((payload.len() as u32).to_le_bytes());
        out.extend(body);
        out
    }

    #[test]
    fn walks_the_header_and_inflates() {
        let doc = activemime(b"payload", 4, None);
        assert_eq!(parse_active_mime(&doc), Some(Ok(b"payload".to_vec())));
        let mut trailing = doc.clone();
        trailing.extend(b"junk");
        assert_eq!(parse_active_mime(&trailing), Some(Ok(b"payload".to_vec())));
        assert_eq!(parse_active_mime(b"activemime"), None);
        assert_eq!(parse_active_mime(b"xActiveMime"), None);
    }

    #[test]
    fn malformed_documents_are_refused() {
        assert!(matches!(
            parse_active_mime(&activemime(b"p", 8, None)),
            Some(Err(Malformed::Field(_, _)))
        ));
        assert!(matches!(
            parse_active_mime(b"ActiveMime"),
            Some(Err(Malformed::Field(12, _)))
        ));
        assert!(matches!(
            parse_active_mime(&activemime(b"p", 4, Some(b"\x78\x9cbad".to_vec()))),
            Some(Err(Malformed::Payload(_)))
        ));
    }
}
