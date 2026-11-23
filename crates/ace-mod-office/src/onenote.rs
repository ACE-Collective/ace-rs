//! `onenote_extraction`: ace3's `OneNoteFileAnalyzer` (`saq/modules/file_analysis/one_note.py`),
//! with the `FileDataStoreObject` struct of `saq/onenote.py`.
//!
//! A file named `.one`, or starting with OneNote's header GUID, is tagged `onenote`, and its first
//! `max_bytes` are searched for the `FileDataStoreObject` GUID. At each match, not overlapping the
//! last, the object is read as construct reads it: the GUID, a 64-bit length, 12 bytes and that
//! many bytes of data, written to `<file>.extracted-<first 6 hex of its sha256>`, `extracted_from`
//! the file and typed `document.onenote.embedded`. An object that runs past the bytes read raises
//! out of ace3's module, which keeps what it wrote before, so the result here stops there too. ace3's
//! engine marks that analysis failed with the exception, construct's `StreamError`, and so is the
//! result here (`ResultEnvelope::error`), in ace3's words without its crash report's id.
//!
//! Where ace-rs departs: ace3's root takes at most 500 files, the file itself one of them, so this writes at most 499. Two
//! payloads whose sha256 start alike overwrite one file in ace3, with both observables naming it;
//! here the first is written and the second is only listed.

use ace_results::FileRole;
use ace_results::types::office::OneNoteFileAnalysis;
use ace_results::{AnalysisType, ObservableKind, ResultEnvelope};
use ace_sdk::takes::{Case, Condition, Takes, Text, TypeFact};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{MAX_FILES, extracted_from, item_list};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<OneNoteAnalyzer>();

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

/// The payloads of the objects found in `data`, in order, and what construct raised reading one
/// that runs past the bytes: `str()` of its `StreamError`, which names the struct's field.
pub fn payloads(data: &[u8]) -> (Vec<&[u8]>, Option<String>) {
    let mut found = Vec::new();
    let mut at = 0;
    // construct's stream_read: `Error in path <path>` and how much the stream was short by
    let short = |field: &str, expected: u64, left: usize| {
        format!(
            "Error in path (parsing) -> FileDataStoreObject{field}\nstream read less than \
             specified amount, expected {expected}, found {left}"
        )
    };
    while let Some(offset) = memchr::memmem::find(&data[at..], &FILE_DATA_STORE_OBJECT) {
        let start = at + offset;
        // guidHeader, cbLength, 4 and 8 unnamed bytes, FileData
        let object = &data[start..];
        let Some(length) = object.get(16..24) else {
            return (found, Some(short(" -> cbLength", 8, object.len() - 16)));
        };
        let length = u64::from_le_bytes(length.try_into().expect("8 bytes"));
        // the two unnamed fields, which construct's path doesn't name
        if object.len() < 28 {
            return (found, Some(short("", 4, object.len() - 24)));
        }
        if object.len() < 36 {
            return (found, Some(short("", 8, object.len() - 28)));
        }
        let end = usize::try_from(length)
            .ok()
            .and_then(|length| length.checked_add(36));
        match end.and_then(|end| object.get(36..end)) {
            Some(payload) => found.push(payload),
            // Python's read() takes no length past a ssize_t, which construct reports as its own
            None if length > i64::MAX as u64 => {
                let raised = format!(
                    "Error in path (parsing) -> FileDataStoreObject -> FileData\nstream.read() \
                     failed, requested {length} bytes"
                );
                return (found, Some(raised));
            }
            None => {
                return (
                    found,
                    Some(short(" -> FileData", length, object.len() - 36)),
                );
            }
        }
        at = start + FILE_DATA_STORE_OBJECT.len();
    }
    (found, None)
}

impl Module for OneNoteAnalyzer {
    const NAME: &'static str = OneNoteFileAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    type Output = OneNoteFileAnalysis;
    type Settings = OneNoteSettings;

    fn init(_: &OneNoteSettings) -> Result<Self, ModuleError> {
        Ok(OneNoteAnalyzer)
    }

    fn takes(_: &OneNoteSettings) -> Takes {
        Takes::everything()
            .and(Condition::not_empty(), "an empty file")
            // `is_onenote_file`: the name, then the header, which the type step tests (PLAN.md
            // decision 25)
            .and(
                Condition::Any(vec![
                    Condition::Name(Text::ends_with(".one", Case::Lower)),
                    Condition::type_fact(TypeFact::HasOnenoteHeader),
                ]),
                "not a OneNote file",
            )
    }
}

impl Parser for OneNoteAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<OneNoteSettings>,
    ) -> Result<Outcome<OneNoteFileAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let mut data = Vec::new();
        {
            use std::io::Read;
            std::fs::File::open(&file.local_path)?
                .take(ctx.settings().max_bytes)
                .read_to_end(&mut data)?;
        }
        let (found, raised) = payloads(&data);
        if let Some(raised) = &raised {
            tracing::info!("a FileDataStoreObject runs past the bytes read: {raised}");
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
            let mut new_file =
                ctx.write_file(&path, payload, FileRole::DOCUMENT_ONENOTE_EMBEDDED)?;
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
        // as ace3's engine marks the analysis its module raised out of: `<type>: <message>`
        result.error = raised.map(|raised| format!("StreamError: {raised}"));
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
        assert_eq!(raised, None);
        assert_eq!(found, vec![&outer_payload[..], b"inner"]);
    }

    #[test]
    fn a_short_object_stops_the_search() {
        let mut data = object(b"one", 3);
        data.extend(object(b"short", 1000));
        let (found, raised) = payloads(&data);
        // construct's StreamError, naming the field it was reading
        let in_path = "Error in path (parsing) -> FileDataStoreObject";
        let short = "stream read less than specified amount";
        assert_eq!(
            raised,
            Some(format!(
                "{in_path} -> FileData\n{short}, expected 1000, found 5"
            ))
        );
        assert_eq!(found, vec![&b"one"[..]]);
        assert_eq!(
            payloads(&FILE_DATA_STORE_OBJECT[..]),
            (
                vec![],
                Some(format!(
                    "{in_path} -> cbLength\n{short}, expected 8, found 0"
                ))
            )
        );
        // the 4 and 8 bytes the struct doesn't name, so the path doesn't either
        let whole = object(b"", 0);
        assert_eq!(
            payloads(&whole[..26]),
            (
                vec![],
                Some(format!("{in_path}\n{short}, expected 4, found 2"))
            )
        );
        assert_eq!(
            payloads(&whole[..33]),
            (
                vec![],
                Some(format!("{in_path}\n{short}, expected 8, found 5"))
            )
        );
        // a length Python's read() can't take
        assert_eq!(
            payloads(&object(b"", u64::MAX)),
            (
                vec![],
                Some(format!(
                    "{in_path} -> FileData\nstream.read() failed, requested {} bytes",
                    u64::MAX
                ))
            )
        );
    }
}
