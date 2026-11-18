//! The checks of ace3's `saq/modules/file_analysis/is_file_type.py` that `file_type` runs, on the
//! file's alert path and bytes, and the first-byte tests of the modules that decide by them, which
//! the type step makes for them so they declare on the answers (PLAN.md decision 25). ace3 runs
//! them on the file's path on its node, which ends with the alert path, so a check on the name
//! gives the same answer.

use ace_mod_oletools::pyzip::ZipFile;

pub use ace_results::types::file_type::{KNOWN_OFFICE_EXTENSIONS, is_office_ext};

const OLE_MAGIC: &[u8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";
const LNK_MAGIC: &[u8] = b"\x4C\x00\x00\x00\x01\x14\x02\x00";

pub fn is_ole_file(data: &[u8]) -> bool {
    data.starts_with(OLE_MAGIC)
}

/// `data[:3] == b'\\rt' or data == b'{\\rt'` of the first four bytes.
pub fn is_rtf_file(data: &[u8]) -> bool {
    data.starts_with(b"\\rt") || data.starts_with(b"{\\rt")
}

/// `%PDF-` in the first 1024 bytes, except for the PDF module's `.pdfparser` output.
pub fn is_pdf_file(path: &str, data: &[u8]) -> bool {
    ace_results::types::file_type::is_pdf_file(path, has_pdf_marker(data))
}

/// `%PDF-` in the first 1024 bytes: `is_pdf_file`'s check of the bytes.
pub fn has_pdf_marker(data: &[u8]) -> bool {
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

/// libpcap's magic numbers, in both byte orders, with micro- and nanosecond timestamps (ace3's
/// `PCAP_MAGIC_BYTES`).
const PCAP_MAGIC_BYTES: [&[u8; 4]; 4] = [
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
];
/// A pcapng section header block's type (`PCAPNG_SECTION_HEADER`).
const PCAPNG_SECTION_HEADER: &[u8; 4] = b"\x0a\x0d\x0d\x0a";
/// Its byte-order magics, little-endian, then big-endian (`PCAPNG_BYTE_ORDER_MAGICS`).
const PCAPNG_BYTE_ORDER_MAGICS: [&[u8; 4]; 2] = [b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"];
const ONENOTE_HEADER: [u8; 16] = [
    0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8, 0xa7, 0x4d, 0xae, 0xb1, 0x53, 0x78, 0xd0, 0x29, 0x96, 0xd3,
];

/// ace3's `is_pcap_file`, on the first 12 bytes: a pcap magic number, or a pcapng section header
/// whose byte-order magic is at bytes 8 to 12. The pcapng block type alone is LF CR CR LF, which
/// text can start with. libmagic names both formats, but a pcapng with an unknown byte order or a
/// file shorter than its record isn't told apart the same way, so the module's own test is the
/// fact.
pub fn is_pcap_file(data: &[u8]) -> bool {
    let header = &data[..data.len().min(12)];
    if header.len() >= 4 && PCAP_MAGIC_BYTES.iter().any(|m| &header[..4] == *m) {
        return true;
    }
    header.len() == 12
        && &header[..4] == PCAPNG_SECTION_HEADER
        && PCAPNG_BYTE_ORDER_MAGICS
            .iter()
            .any(|m| &header[8..12] == *m)
}

/// The part of ace3's `is_onenote_file` that reads the bytes: the first 16 are OneNote's header
/// GUID. The rest of it, a name ending `.one` in any case, is a declaration over the path.
pub fn has_onenote_header(data: &[u8]) -> bool {
    data.get(..16) == Some(&ONENOTE_HEADER[..])
}

/// ace3's `is_java_class_file`: `fp.read(4) == b'\xCA\xFE\xBA\xBE'`.
pub fn is_java_class_file(data: &[u8]) -> bool {
    data.get(..4) == Some(b"\xca\xfe\xba\xbe")
}

/// `b'<?xml' in fp.read(1024)`: the test of ace3's `xml_binary_analyzer` and
/// `xml_plain_text_analyzer`. libmagic's XML rule wants the marker at the start, after a byte-order
/// mark at most; this finds it anywhere in the first kilobyte, as the modules do.
pub fn has_xml_marker(data: &[u8]) -> bool {
    data[..data.len().min(1024)]
        .windows(5)
        .any(|w| w == b"<?xml")
}

/// ace3's `BinaryFileAnalyzer._is_eps`: the first four bytes are the EPS binary header
/// `C5D0D3C6`, or the first eleven are `%!PS-Adobe-`.
pub fn is_eps_file(data: &[u8]) -> bool {
    data.get(..4) == Some(b"\xc5\xd0\xd3\xc6") || data.get(..11) == Some(b"%!PS-Adobe-")
}

/// ace3's `microsoft_script_encoding_analysis`: `fp.read(4) == b'#@~^'`.
pub fn is_encoded_script(data: &[u8]) -> bool {
    data.get(..4) == Some(b"#@~^")
}

/// How much of a file ace3's `har_extraction` reads for its header (`HAR_HEADER_PEEK_BYTES`).
const HAR_HEADER_PEEK_BYTES: usize = 4096;
/// `RE_HAR_HEADER`, `rb'^\s*\{\s*"log"\s*:'`: a bytes pattern, whose `\s` is ASCII whitespace,
/// as `(?-u)` makes Rust's.
static RE_HAR_HEADER: std::sync::LazyLock<regex::bytes::Regex> = std::sync::LazyLock::new(|| {
    regex::bytes::Regex::new(r#"(?-u)^\s*\{\s*"log"\s*:"#).expect("the pattern compiles")
});

/// ace3's `is_har_header(fp.read(HAR_HEADER_PEEK_BYTES))`: `RE_HAR_HEADER.match` on the first
/// 4096 bytes.
pub fn has_har_header(data: &[u8]) -> bool {
    RE_HAR_HEADER.is_match(&data[..data.len().min(HAR_HEADER_PEEK_BYTES)])
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

    #[test]
    fn the_modules_first_byte_tests() {
        // pcap in both byte orders and timestamp kinds, and pcapng only with a byte-order magic
        for magic in PCAP_MAGIC_BYTES {
            assert!(is_pcap_file(magic));
        }
        assert!(!is_pcap_file(b"\xd4\xc3\xb2"));
        let mut pcapng = b"\x0a\x0d\x0d\x0a\x1c\x00\x00\x00\x4d\x3c\x2b\x1a".to_vec();
        assert!(is_pcap_file(&pcapng));
        pcapng[8] = 0;
        assert!(!is_pcap_file(&pcapng));
        assert!(!is_pcap_file(&pcapng[..11]));
        assert!(!is_pcap_file(b"\n\r\r\nsome text"));
        assert!(has_onenote_header(&ONENOTE_HEADER));
        assert!(!has_onenote_header(&ONENOTE_HEADER[..15]));
        assert!(is_java_class_file(b"\xca\xfe\xba\xbe\x00\x00"));
        assert!(!is_java_class_file(b"\xca\xfe\xba"));
        // anywhere in the first kilobyte, after a byte-order mark or whitespace too
        assert!(has_xml_marker(b"\xef\xbb\xbf<?xml version='1.0'?>"));
        assert!(has_xml_marker(b"  \n<?xml"));
        let mut late = vec![b' '; 1020];
        late.extend(b"<?xml");
        assert!(!has_xml_marker(&late));
        late.drain(..1);
        assert!(has_xml_marker(&late));
        assert!(is_eps_file(b"\xc5\xd0\xd3\xc6rest"));
        assert!(is_eps_file(b"%!PS-Adobe-3.0 EPSF-3.0"));
        assert!(!is_eps_file(b"%!PS-Adobe"));
        assert!(is_encoded_script(b"#@~^AAAA"));
        assert!(!is_encoded_script(b" #@~^"));
        assert!(has_har_header(b" \n{ \"log\" :{"));
        assert!(has_har_header(b"\x0b\x0c{\"log\":"));
        assert!(!has_har_header(b"\xef\xbb\xbf{\"log\":"));
        let mut far = vec![b' '; 4090];
        far.extend(b"{\"log\":");
        assert!(!has_har_header(&far));
    }
}
