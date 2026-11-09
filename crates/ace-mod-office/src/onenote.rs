//! `onenote_extraction`: ace3's `OneNoteFileAnalyzer` (`saq/modules/file_analysis/one_note.py`),
//! with the `FileDataStoreObject` struct of `saq/onenote.py`.
//!
//! A file named `.one`, or starting with OneNote's header GUID, is tagged `onenote`, and its first
//! `max_bytes` are searched for the `FileDataStoreObject` GUID. At each match, not overlapping the
//! last, the object is read as construct reads it: the GUID, a 64-bit length, 12 bytes and that
//! many bytes of data, written to `<file>.extracted-<first 6 hex of its sha256>`, `extracted_from`
//! the file and typed `document.onenote.embedded`. An object that runs past the bytes read raises
//! out of ace3's module, which keeps what it wrote before, so the result here stops there too.
//!
//! Where ace4 departs: ace3's root takes at most 500 files, the file itself one of them, so this writes at most 499. Two
//! payloads whose sha256 start alike overwrite one file in ace3, with both observables naming it;
//! here the first is written and the second is only listed.

use ace_results::types::office::OneNoteFileAnalysis;
use ace_results::{AnalysisType, ObservableKind, ResultEnvelope, YaraMeta};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{MAX_FILES, extracted_from, item_list};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<OneNoteAnalyzer>();

const ONENOTE_HEADER: [u8; 16] = [
    0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8, 0xa7, 0x4d, 0xae, 0xb1, 0x53, 0x78, 0xd0, 0x29, 0x96, 0xd3,
];
const FILE_DATA_STORE_OBJECT: [u8; 16] = [
    0xe7, 0x16, 0xe3, 0xbd, 0x65, 0x26, 0x11, 0x45, 0xa4, 0xc4, 0x8d, 0x4d, 0x0b, 0x7a, 0x9e, 0xac,
];

/// ace3's settings of the module.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct OneNoteSettings {
    /// How much of the file is searched.
    pub max_bytes: u64,
}

impl Default for OneNoteSettings {
    fn default() -> Self {
        OneNoteSettings {
            max_bytes: 100 * 1024 * 1024,
        }
    }
}

pub struct OneNoteAnalyzer;

/// `is_onenote_file`: the name, then the header.
pub fn is_onenote_file(name: &str, data: &[u8]) -> bool {
    ace_pycompat::pystr::lower(name).ends_with(".one") || data.get(..16) == Some(&ONENOTE_HEADER)
}

/// The payloads of the objects found in `data`, in order, and whether reading one raised.
pub fn payloads(data: &[u8]) -> (Vec<&[u8]>, bool) {
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(offset) = memchr::memmem::find(&data[at..], &FILE_DATA_STORE_OBJECT) {
        let start = at + offset;
        // guidHeader, cbLength, 4 and 8 unused bytes, FileData
        let object = &data[start..];
        let Some(length) = object.get(16..24) else {
            return (found, true);
        };
        let length = u64::from_le_bytes(length.try_into().expect("8 bytes"));
        let end = usize::try_from(length)
            .ok()
            .and_then(|length| length.checked_add(36));
        match end.and_then(|end| object.get(36..end)) {
            Some(payload) => found.push(payload),
            None => return (found, true),
        }
        at = start + FILE_DATA_STORE_OBJECT.len();
    }
    (found, false)
}

impl Module for OneNoteAnalyzer {
    const NAME: &'static str = OneNoteFileAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    type Output = OneNoteFileAnalysis;
    type Settings = OneNoteSettings;

    fn init(_: &OneNoteSettings) -> Result<Self, ModuleError> {
        Ok(OneNoteAnalyzer)
    }
}

impl Parser for OneNoteAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<OneNoteSettings>,
    ) -> Result<Outcome<OneNoteFileAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        if file.size == 0 {
            return Ok(Outcome::Skipped("an empty file".to_owned()));
        }
        let mut header = Vec::new();
        let mut data = Vec::new();
        {
            use std::io::Read;
            std::fs::File::open(&file.local_path)?
                .take(16)
                .read_to_end(&mut header)?;
            std::fs::File::open(&file.local_path)?
                .take(ctx.settings().max_bytes)
                .read_to_end(&mut data)?;
        }
        if !is_onenote_file(file.name(), &header) {
            return Ok(Outcome::Skipped("not a OneNote file".to_owned()));
        }
        let meta =
            YaraMeta::new("type", "document.onenote.embedded").map_err(ModuleError::other)?;
        let (found, raised) = payloads(&data);
        if raised {
            tracing::info!("a FileDataStoreObject runs past the bytes read");
        }
        let mut analysis = OneNoteFileAnalysis::default();
        let mut files = Vec::new();
        for payload in found {
            if files.len() >= MAX_FILES {
                break;
            }
            ctx.check_cancelled()?;
            let hex: String = Sha256::digest(payload)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let path = format!("{}.extracted-{}", file.path, &hex[..6]);
            analysis.extracted_files.push(hex);
            // the same name again is the same file to ace3's root
            if files
                .iter()
                .any(|f: &ace_results::NewFile| f.path.as_str() == path)
            {
                continue;
            }
            let mut new_file = ctx.write_file(&path, payload, std::slice::from_ref(&meta))?;
            new_file.relationships.push(extracted_from(file));
            files.push(new_file);
        }
        let summary = (!analysis.extracted_files.is_empty()).then(|| {
            format!(
                "OneNote File Analysis: extracted files {}",
                item_list(&analysis.extracted_files)
            )
        });
        let mut result = ResultEnvelope::new(analysis);
        result.summary = summary;
        result.analyzed.add_tag("onenote");
        result.files = files;
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(payload: &[u8], length: u64) -> Vec<u8> {
        let mut out = FILE_DATA_STORE_OBJECT.to_vec();
        out.extend(length.to_le_bytes());
        out.extend([0; 12]);
        out.extend(payload);
        out
    }

    #[test]
    fn objects_are_read_in_order_and_inside_each_other() {
        let inner = object(b"inner", 5);
        let mut outer_payload = b"outer ".to_vec();
        outer_payload.extend(&inner);
        let mut data = b"junk".to_vec();
        data.extend(object(&outer_payload, outer_payload.len() as u64));
        let (found, raised) = payloads(&data);
        assert!(!raised);
        assert_eq!(found, vec![&outer_payload[..], b"inner"]);
    }

    #[test]
    fn a_short_object_stops_the_search() {
        let mut data = object(b"one", 3);
        data.extend(object(b"short", 1000));
        let (found, raised) = payloads(&data);
        assert!(raised);
        assert_eq!(found, vec![&b"one"[..]]);
        assert_eq!(payloads(&FILE_DATA_STORE_OBJECT[..]), (vec![], true));
        assert_eq!(payloads(&object(b"", u64::MAX)), (vec![], true));
    }

    #[test]
    fn a_onenote_file_is_named_or_headed() {
        assert!(is_onenote_file("A.ONE", b""));
        assert!(is_onenote_file("x.bin", &ONENOTE_HEADER));
        assert!(!is_onenote_file("x.bin", &ONENOTE_HEADER[..15]));
    }
}
