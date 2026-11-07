//! Whether a workbook has an Excel 4 macro sheet. olevba asks XLMMacroDeobfuscator, and falls back on
//! oledump's plugin_biff, and both give their whole output as the module's text; PLAN.md 4.12 ports
//! that. Until then this keeps the part ace3's tags and summary depend on, the `XLM macro` keyword, so
//! a macro sheet beside VBA is still flagged.

use crate::ole::OleFile;
use crate::pyxml;
use crate::pyzip::ZipFile;

const BOUNDSHEET: u16 = 0x0085;

fn biff_has_macro_sheet(stream: &[u8]) -> bool {
    let mut at = 0;
    while let Some(header) = stream.get(at..at + 4) {
        let kind = u16::from_le_bytes([header[0], header[1]]);
        let size = usize::from(u16::from_le_bytes([header[2], header[3]]));
        let Some(body) = stream.get(at + 4..at + 4 + size) else {
            return false;
        };
        // BOF of a later substream ends the globals
        if kind == 0x0809 && at != 0 {
            return false;
        }
        if kind == BOUNDSHEET
            && body
                .get(5)
                .is_some_and(|&sheet_type| sheet_type & 0x0F == 1)
        {
            return true;
        }
        at += 4 + size;
    }
    false
}

/// `data` is the whole file, and `ole` is open when the file is OLE.
pub(crate) fn has_macro_sheet(data: &[u8], ole: Option<&mut OleFile>) -> bool {
    if let Some(ole) = ole {
        for name in ["Workbook", "Book"] {
            if ole.exists(name)
                && let Ok(stream) = ole.read_stream(name)
                && biff_has_macro_sheet(&stream)
            {
                return true;
            }
        }
        return false;
    }
    let Ok(zip) = ZipFile::new(data) else {
        return false;
    };
    let names: Vec<String> = zip.namelist().into_iter().map(str::to_owned).collect();
    names
        .iter()
        .filter(|name| name.contains("_rels/workbook"))
        .any(|rels| {
            let Some(rels) = zip
                .read(rels)
                .ok()
                .and_then(|xml| pyxml::fromstring(&xml).ok())
            else {
                return false;
            };
            let tag = "{http://schemas.openxmlformats.org/package/2006/relationships}Relationship";
            rels.iter_tag(tag).into_iter().any(|relationship| {
                let kind = relationship.get("Type").unwrap_or_default();
                let target = relationship
                    .get("Target")
                    .unwrap_or_default()
                    .trim_start_matches('/');
                // a sheet with a formula in it: an empty sheet gives XLMMacroDeobfuscator nothing to say
                kind.ends_with("/xlMacrosheet")
                    && names.iter().any(|name| {
                        name.ends_with(target)
                            && zip
                                .read(name)
                                .is_ok_and(|sheet| memchr::memmem::find(&sheet, b"<f").is_some())
                    })
            })
        })
}
