//! The checks of ace3's `saq/modules/file_analysis/is_file_type.py` that `file_type` runs, on the
//! file's alert path and bytes. ace3 runs them on the file's path on its node, which ends with the
//! alert path, so a check on the name gives the same answer.

use ace_mod_oletools::ftguess::splitext;
use ace_mod_oletools::pyzip::ZipFile;

/// `KNOWN_OFFICE_EXTENSIONS`.
pub const KNOWN_OFFICE_EXTENSIONS: &[&str] = &[
    "doc", "docb", "dochtml", "docm", "docx", "docxml", "dot", "dothtml", "dotm", "dotx", "odt",
    "rtf", "wbk", "wiz", "csv", "dqy", "iqy", "odc", "ods", "slk", "xla", "xlam", "xlk", "xll",
    "xlm", "xls", "xlsb", "xlshtml", "xlsm", "xlsx", "xlt", "xlthtml", "xltm", "xltx", "xlw",
    "odp", "pot", "pothtml", "potm", "potx", "ppa", "ppam", "pps", "ppsm", "ppsx", "ppt",
    "ppthtml", "pptm", "pptx", "pptxml", "pwz", "sldm", "sldx", "thmx",
];

const OLE_MAGIC: &[u8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";
const LNK_MAGIC: &[u8] = b"\x4C\x00\x00\x00\x01\x14\x02\x00";

/// `is_office_ext`: `os.path.splitext`'s extension, as it is, in the list.
pub fn is_office_ext(path: &str) -> bool {
    splitext(path)
        .1
        .strip_prefix('.')
        .is_some_and(|ext| KNOWN_OFFICE_EXTENSIONS.contains(&ext))
}

pub fn is_ole_file(data: &[u8]) -> bool {
    data.starts_with(OLE_MAGIC)
}

/// `data[:3] == b'\\rt' or data == b'{\\rt'` of the first four bytes.
pub fn is_rtf_file(data: &[u8]) -> bool {
    data.starts_with(b"\\rt") || data.starts_with(b"{\\rt")
}

/// `%PDF-` in the first 1024 bytes, except for the PDF module's `.pdfparser` output.
pub fn is_pdf_file(path: &str, data: &[u8]) -> bool {
    if path.ends_with(".pdfparser") {
        return false;
    }
    data[..data.len().min(1024)]
        .windows(5)
        .any(|w| w == b"%PDF-")
}

pub fn is_pe_file(data: &[u8]) -> bool {
    data.starts_with(b"MZ")
}

pub fn is_lnk_file(data: &[u8]) -> bool {
    data.starts_with(LNK_MAGIC)
}

/// The names `zipfile.ZipFile` lists, when it opens the file.
pub fn zip_names(data: &[u8]) -> Option<Vec<String>> {
    let zip = ZipFile::new(data).ok()?;
    Some(zip.namelist().into_iter().map(str::to_owned).collect())
}

/// What Python's `open(path, "r", encoding="utf-8")` gives `is_email_file`: its lines, read
/// in chunks of 8192 bytes, with universal newlines. A chunk that doesn't decode raises
/// `UnicodeDecodeError` when it is read, which is the check's False.
const CHUNK: usize = 8192;

/// `is_email_file`: the file's first lines are 7-bit ASCII headers, and From, Subject and
/// Message-ID come before the first line that isn't one.
pub fn is_email_file(data: &[u8]) -> bool {
    const COMMON: [&str; 3] = ["from", "subject", "message-id"];
    // where decoding would fail, as the number of bytes that must be read to see it
    let decode_error_at = match std::str::from_utf8(data) {
        Ok(_) => None,
        Err(e) => Some(match e.error_len() {
            Some(len) => e.valid_up_to() + len,
            // an incomplete sequence at the end fails on the read that finds the end
            None => data.len() + 1,
        }),
    };
    let mut found: Vec<&str> = Vec::new();
    let mut start = 0;
    while start < data.len() {
        // a line ends at \n, \r\n or \r; a lone \r needs the next byte to tell
        let (end, needed) = match data[start..]
            .iter()
            .position(|b| *b == b'\n' || *b == b'\r')
        {
            // the line runs to the end, which takes one more read to find
            None => (data.len(), data.len() + 1),
            Some(at) => {
                let at = start + at;
                if data[at] == b'\r' {
                    if data.get(at + 1) == Some(&b'\n') {
                        (at + 2, at + 2)
                    } else {
                        (at + 1, at + 2)
                    }
                } else {
                    (at + 1, at + 1)
                }
            }
        };
        // TextIOWrapper decodes whole chunks
        let read = if needed > data.len() {
            needed
        } else {
            needed.div_ceil(CHUNK).saturating_mul(CHUNK).min(data.len())
        };
        if decode_error_at.is_some_and(|at| at <= read) {
            return false;
        }
        let line = &data[start..end];
        start = end;
        // universal newlines make the terminator one \n
        let body = line
            .strip_suffix(b"\r\n")
            .or_else(|| line.strip_suffix(b"\n"))
            .or_else(|| line.strip_suffix(b"\r"))
            .unwrap_or(line);
        if !body.is_ascii() {
            return false;
        }
        // RE_EMAIL_HEADER_INDENTED: whitespace, then something that isn't
        let indent = body.iter().take_while(|b| is_py_space(**b)).count();
        if indent > 0 && indent < body.len() {
            continue;
        }
        // the line is blank
        if indent == body.len() {
            return false;
        }
        // RE_EMAIL_HEADER: a name of letters, digits and dashes, then a colon
        let name_len = body
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || **b == b'-')
            .count();
        if name_len == 0 || body.get(name_len) != Some(&b':') {
            return false;
        }
        let name = std::str::from_utf8(&body[..name_len])
            .unwrap_or_default()
            .to_ascii_lowercase();
        if let Some(common) = COMMON.iter().find(|c| **c == name)
            && !found.contains(common)
        {
            found.push(common);
        }
        if found.len() == COMMON.len() {
            return true;
        }
    }
    false
}

/// `str.isspace()` for an ASCII character, which is also what `\s` matches in a `str` pattern.
fn is_py_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c | 0x1c..=0x1f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_headers_in_any_line_ending() {
        let email =
            b"From: a@b\r\nSubject: hi\r\nX-A: 1\r\n  folded\r\nMessage-ID: <1@b>\r\n\r\nbody";
        assert!(is_email_file(email));
        let lone_cr: Vec<u8> = email.iter().copied().filter(|b| *b != b'\n').collect();
        assert!(is_email_file(&lone_cr));
        let lf: Vec<u8> = email.iter().copied().filter(|b| *b != b'\r').collect();
        assert!(is_email_file(&lf));
        assert!(!is_email_file(b"From: a@b\n\nSubject: x\nMessage-ID: y\n"));
        assert!(!is_email_file(
            b"From: a@b\nSubject: \xc3\xa9\nMessage-ID: y\n"
        ));
        assert!(!is_email_file(b"From a@b\nSubject: x\nMessage-ID: y\n"));
        // an undecodable byte in the chunk that holds the last header
        assert!(!is_email_file(
            b"From: a\nSubject: b\nMessage-ID: c\n\n\xff"
        ));
        // an incomplete sequence at the end is seen only by a read past it
        assert!(is_email_file(b"From: a\nSubject: b\nMessage-ID: c\n\xe2"));
        assert!(!is_email_file(b"From: a\nSubject: b\n\xe2"));
        // and one that's past the first chunk
        let mut long = b"From: a\nSubject: b\nMessage-ID: c\n\n".to_vec();
        long.resize(CHUNK + 10, b'x');
        long.push(0xff);
        assert!(is_email_file(&long));
    }

    #[test]
    fn the_name_and_magic_checks() {
        assert!(is_office_ext("a/b.docx"));
        assert!(!is_office_ext("a/b.DOCX"));
        assert!(!is_office_ext(".docx"));
        assert!(is_rtf_file(b"{\\rtf1"));
        assert!(is_rtf_file(b"\\rtx"));
        assert!(!is_rtf_file(b"{\\r"));
        assert!(is_pdf_file("a.pdf", b"junk%PDF-1.4"));
        assert!(!is_pdf_file("a.pdfparser", b"%PDF-1.4"));
    }
}
