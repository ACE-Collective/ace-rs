//! What olevba's fallback gets from oledump's plugin_biff, when XLMMacroDeobfuscator raises or the file
//! isn't on disk: `cBIFF(options='-o BOUNDSHEET').Analyze()`, the list of a workbook's sheets, which olevba
//! yields as its `xlm_macro` macro.
//!
//! When that list names a macro sheet olevba also asks for its labels, its formulas as CSV and its DCONN
//! records. Those take plugin_biff's formula parser, about 5,000 lines, so they aren't ported, and only the
//! CSV's heading is here. The file is still flagged, and it reached here because xlrd2 refused it, so ace3's
//! own module has no text for it either. PLAN.md 4.12 says so.

use crate::ole::OleFile;

fn opcode_name(opcode: u16) -> &'static str {
    match opcode {
        0x85 => "BOUNDSHEET : Sheet Information",
        _ => "",
    }
}

/// `ShortXLUnicodeString`. None is its IndexError, which ends the plugin's run on this stream.
fn short_string(data: &[u8], is_biff8: bool) -> Option<String> {
    let count = usize::from(*data.first()?);
    if is_biff8 {
        let high_byte = *data.get(1)?;
        let rest = data.get(2..).unwrap_or(&[]);
        if high_byte == 0 {
            Some(p23_decode(&rest[..count.min(rest.len())]))
        } else {
            Some(crate::py::repr_bytes(&rest[..(count * 2).min(rest.len())]))
        }
    } else {
        let rest = data.get(1..).unwrap_or(&[]);
        Some(p23_decode(&rest[..count.min(rest.len())]))
    }
}

fn p23_decode(data: &[u8]) -> String {
    match std::str::from_utf8(data) {
        Ok(text) => text.to_owned(),
        Err(_) => crate::codepage::Decoder::cp1252().decode(data),
    }
}

/// The lines `-o BOUNDSHEET` gives for a stream, and whether one is a macro sheet.
fn boundsheets(stream: &[u8]) -> Option<(Vec<String>, bool)> {
    let mut lines = Vec::new();
    let mut macro_sheet = false;
    let mut filepass = false;
    let mut is_biff8 = true;
    let mut position = 0;
    while let Some(header) = stream.get(position..position + 4) {
        let opcode = u16::from_le_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        let start = position + 4;
        let data = stream
            .get(start..(start + length).min(stream.len()))
            .unwrap_or(&[]);
        position = start + length;
        if opcode == 0x2F {
            filepass = true;
        }
        // the library compares its dict of versions with 0x0600, so any BOF means not BIFF8
        if opcode == 0x0809 && data.len() >= 8 && !filepass {
            is_biff8 = false;
        }
        let mut line = format!("{opcode:04x} {length:6} {}", opcode_name(opcode));
        if opcode == 0x85 && data.len() >= 6 && !filepass {
            let (state, kind) = (data[4], data[5]);
            let kind_name = match kind {
                0 => "worksheet or dialog sheet".to_owned(),
                1 => {
                    macro_sheet = true;
                    "Excel 4.0 macro sheet".to_owned()
                }
                2 => "chart".to_owned(),
                6 => "Visual Basic module".to_owned(),
                other => format!("{other:02x}"),
            };
            let name = short_string(&data[6..], is_biff8)?;
            let mut visibility = String::new();
            if state > 3 {
                visibility = format!("reserved bits not zero: 0x{:02x} ", state & 0xFC);
            }
            visibility.push_str(match state & 3 {
                0 => "visible",
                1 => "hidden",
                2 => "very hidden",
                _ => "visibility=3",
            });
            line.push_str(&format!(" - {kind_name}, {visibility} - {name}"));
        }
        if line.to_lowercase().contains("boundsheet") {
            lines.push(line);
        }
    }
    if filepass {
        lines.push("Warning: FILEPASS record found, file is password protected".to_owned());
    }
    Some((lines, macro_sheet))
}

/// `_extract_xlm_plugin_biff`: the lines olevba keeps, and whether it found an XLM macro.
pub(crate) fn plugin_biff(ole: &mut OleFile) -> (Vec<String>, bool) {
    let mut kept = Vec::new();
    for name in ["Workbook", "Book"] {
        if ole.exists(name)
            && let Ok(stream) = ole.read_stream(name)
            && let Some((lines, found)) = boundsheets(&stream)
        {
            kept = lines;
            if found {
                kept.push("Sheet,Reference,Formula,Value".to_owned());
                return (kept, true);
            }
        }
    }
    (kept, false)
}

/// `open_slk`'s lines: a macro sheet's names and formulas, or None for a file that has none.
pub(crate) fn slk_macros(data: &[u8]) -> Option<Vec<String>> {
    let mut found = false;
    let mut lines = vec!["Formulas and XLM/Excel 4 macros extracted from SLK file:".to_owned()];
    for line in data.split(|c| matches!(c, b'\r' | b'\n')) {
        let fields = || line.split(|c| *c == b';').filter(|f| f.starts_with(b"E"));
        if line.starts_with(b"O") {
            if fields().next().is_some() {
                found = true;
            }
        } else if line.starts_with(b"NN") && found {
            for field in fields() {
                lines.push(format!(
                    "Named cell: {}",
                    String::from_utf8_lossy(&field[1..])
                ));
            }
        } else if line.starts_with(b"C") && found {
            for field in fields() {
                lines.push(format!(
                    "Formula or Macro: {}",
                    String::from_utf8_lossy(&field[1..])
                ));
            }
        }
    }
    found.then_some(lines)
}
