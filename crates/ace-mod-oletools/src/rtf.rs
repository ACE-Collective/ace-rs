//! oletools' `rtfobj.process_file(None, name, data, output_dir, save_object='all')`, with `oleobj`'s
//! OLE 1.0 parsing, and tablestream's table. The files it would write stay in memory.
//!
//! Python's parser is quadratic in places where this isn't (`data +=`, the `re.sub` on each `\'`), so
//! a large crafted file finishes here where it would reach the deadline in ace3.

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

use md5::{Digest, Md5};
use regex::bytes::Regex as BytesRegex;

use crate::ole::{OleFile, has_magic};
use crate::py::{PyErr, PyResult, is_word, memory_error, repr_bytes, repr_str, splitlines, strip};
use crate::tables::{DESTINATIONS, KNOWN_CLSIDS};
use crate::{ftguess, textwrap};

/// What one run may hold: of objects decoded, of the report, and of files to save. Past one it raises
/// MemoryError where Python would keep going until it ran out.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub objects: usize,
    pub objects_bytes: usize,
    pub report_bytes: usize,
    pub files: usize,
    pub files_bytes: usize,
}

impl Limits {
    pub const TASK: Limits = Limits {
        objects: 65536,
        objects_bytes: 256 * 1024 * 1024,
        report_bytes: 64 * 1024 * 1024,
        files: 4096,
        files_bytes: 64 * 1024 * 1024,
    };
    /// For comparing with Python on the sample set, which reaches none of the above anyway.
    pub const NONE: Limits = Limits {
        objects: usize::MAX,
        objects_bytes: usize::MAX,
        report_bytes: usize::MAX,
        files: usize::MAX,
        files_bytes: usize::MAX,
    };
}

/// What `process_file` did before it ended or raised.
#[derive(Debug, Default)]
pub struct Report {
    pub stdout: String,
    /// By name in the order first written. A later write of a name replaces its bytes.
    pub files: Vec<(String, Vec<u8>)>,
    pub raised: Option<PyErr>,
}

#[derive(Debug)]
enum ClassName {
    Bytes(Vec<u8>),
    /// A length of zero gives `''`, a str, where the rest is bytes, and that raises later.
    EmptyStr,
}

impl ClassName {
    fn repr(&self) -> String {
        match self {
            ClassName::Bytes(bytes) => repr_bytes(bytes),
            ClassName::EmptyStr => "''".to_owned(),
        }
    }

    fn lower(&self) -> PyResult<Vec<u8>> {
        match self {
            ClassName::Bytes(bytes) => Ok(bytes.to_ascii_lowercase()),
            ClassName::EmptyStr => Err(PyErr::new(
                "TypeError",
                "startswith first arg must be str or a tuple of str, not bytes",
            )),
        }
    }
}

#[derive(Debug, Default)]
struct RtfObject {
    start: usize,
    rawdata: Vec<u8>,
    rawdata_md5: String,
    is_ole: bool,
    format_id: u32,
    class_name: Option<ClassName>,
    oledata_size: Option<u32>,
    oledata: Vec<u8>,
    oledata_md5: String,
    is_package: bool,
    filename: String,
    src_path: String,
    temp_path: String,
    olepkgdata: Vec<u8>,
    olepkgdata_md5: String,
    ftype_name: &'static str,
    clsid: Option<String>,
    clsid_desc: String,
}

fn md5_hex(data: &[u8]) -> String {
    let digest = Md5::digest(data);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Default)]
struct Destination {
    is_objdata: bool,
    data: Vec<u8>,
    /// How much of data has been through the `\'` clean-up, and is only hex digits.
    clean: usize,
    start: usize,
    group_level: i64,
}

struct Parser<'a> {
    data: &'a [u8],
    index: usize,
    group_level: i64,
    destinations: Vec<Destination>,
    /// What `current_destination` holds once the document's destination has been popped.
    popped: Option<Destination>,
    objects: Vec<RtfObject>,
    objects_bytes: usize,
    limits: Limits,
}

fn is_destination(word: &[u8]) -> bool {
    std::str::from_utf8(word).is_ok_and(|word| DESTINATIONS.binary_search(&word).is_ok())
}

/// `re_control_word.match` on the data from a backslash, cropped to 254 bytes plus a space: the
/// name, its parameter and the match's length.
fn control_word(data: &[u8]) -> Option<(&[u8], Option<i128>, usize)> {
    let cropped = &data[..data.len().min(254)];
    let at = |index: usize| -> u8 { cropped.get(index).copied().unwrap_or(b' ') };
    let mut end = 1;
    while end < cropped.len() && cropped[end].is_ascii_alphabetic() && end <= 250 {
        end += 1;
    }
    if end == 1 {
        return None;
    }
    let name = &cropped[1..end];
    // a signed integer that a non-digit follows, which the appended space always can be
    let mut digits = end;
    if at(digits) == b'-' {
        digits += 1;
    }
    let first_digit = digits;
    while digits < cropped.len() && cropped[digits].is_ascii_digit() {
        digits += 1;
    }
    if digits > first_digit {
        let text = std::str::from_utf8(&cropped[end..digits]).unwrap_or("0");
        // a value past i128 is past any file and past zero the same way
        let value =
            text.parse::<i128>()
                .unwrap_or(if text.starts_with('-') { -1 } else { i128::MAX });
        return Some((name, Some(value), digits));
    }
    if !at(end).is_ascii_alphanumeric() {
        return Some((name, None, end));
    }
    None
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8], limits: Limits) -> Parser<'a> {
        Parser {
            data,
            index: 0,
            group_level: 0,
            destinations: vec![Destination::default()],
            popped: None,
            objects: Vec::new(),
            objects_bytes: 0,
            limits,
        }
    }

    fn current(&mut self) -> &mut Destination {
        match self.destinations.last_mut() {
            Some(destination) => destination,
            None => self.popped.get_or_insert_with(Destination::default),
        }
    }

    fn parse(&mut self) -> PyResult<()> {
        let size = self.data.len();
        while self.index < size {
            match self.data[self.index] {
                b'{' => {
                    self.group_level += 1;
                    self.index += 1;
                    continue;
                }
                b'}' => {
                    self.close_group()?;
                    self.index += 1;
                    continue;
                }
                b'\\' => {
                    if let Some((word, parameter, length)) = control_word(&self.data[self.index..])
                    {
                        if is_destination(word) {
                            self.open_destination(word == b"objdata", self.index + length)?;
                        }
                        self.index += length;
                        if word == b"bin" {
                            self.bin(parameter)?;
                        }
                        continue;
                    }
                    if let Some(&symbol) = self.data.get(self.index + 1)
                        && !symbol.is_ascii_alphabetic()
                    {
                        if symbol == b'\'' {
                            self.index += 2;
                            self.clean_hex();
                        }
                        self.index += 2;
                        continue;
                    }
                }
                _ => {}
            }
            let text_end = self.data[self.index..]
                .iter()
                .position(|byte| matches!(byte, b'{' | b'}' | b'\\'))
                .map_or(size, |found| self.index + found);
            if text_end == self.index {
                return Err(PyErr::new(
                    "RuntimeError",
                    format!(
                        "Should not have reached this point - index={:X}h",
                        self.index
                    ),
                ));
            }
            let text = &self.data[self.index..text_end];
            let destination = self.current();
            if destination.is_objdata {
                destination.data.extend_from_slice(text);
            }
            self.index = text_end;
        }
        while self.group_level > 0 {
            self.close_group()?;
        }
        Ok(())
    }

    /// `control_symbol` for `\'`: what's been read of an objdata becomes hex digits only, and an odd
    /// one out goes, which reproduces a bug of Word's. Only what's new since last time needs filtering.
    fn clean_hex(&mut self) {
        let destination = self.current();
        if !destination.is_objdata {
            return;
        }
        let mut kept = destination.clean;
        for at in destination.clean..destination.data.len() {
            let byte = destination.data[at];
            if byte.is_ascii_hexdigit() {
                destination.data[kept] = byte;
                kept += 1;
            }
        }
        destination.data.truncate(kept);
        if destination.data.len() & 1 == 1 {
            destination.data.pop();
        }
        destination.clean = destination.data.len();
    }

    fn bin(&mut self, parameter: Option<i128>) -> PyResult<()> {
        let length = parameter.unwrap_or(0).max(0);
        match self.data.get(self.index) {
            None => {
                return Err(PyErr::new(
                    "TypeError",
                    "ord() expected a character, but string of length 0 found",
                ));
            }
            Some(b' ') => self.index += 1,
            Some(_) => {}
        }
        let end = (self.index as i128).saturating_add(length);
        let to = end.min(self.data.len() as i128) as usize;
        let start = self.index.min(to);
        let data = self.data;
        let destination = self.current();
        if destination.is_objdata {
            for &byte in &data[start..to] {
                destination
                    .data
                    .extend_from_slice(format!("{byte:02x}").as_bytes());
            }
        }
        self.index = end.min(i128::from(u32::MAX) * 1024) as usize;
        Ok(())
    }

    fn close_group(&mut self) -> PyResult<()> {
        if self.group_level == self.current().group_level {
            self.close_destination()?;
        }
        self.group_level -= 1;
        Ok(())
    }

    fn open_destination(&mut self, is_objdata: bool, start: usize) -> PyResult<()> {
        if self.current().group_level == self.group_level {
            self.close_destination()?;
        }
        self.destinations.push(Destination {
            is_objdata,
            start,
            group_level: self.group_level,
            ..Default::default()
        });
        self.popped = None;
        Ok(())
    }

    fn close_destination(&mut self) -> PyResult<()> {
        let Some(destination) = self.destinations.pop() else {
            // closing what's left when the stack is empty: Python's list is empty and stays so
            if self.popped.as_ref().is_some_and(|popped| popped.is_objdata) {
                let popped = self.popped.take().expect("checked");
                self.close_object(&popped)?;
                self.popped = Some(popped);
            }
            return Ok(());
        };
        if destination.is_objdata {
            self.close_object(&destination)?;
        }
        if self.destinations.is_empty() {
            self.popped = Some(destination);
        }
        Ok(())
    }

    fn close_object(&mut self, destination: &Destination) -> PyResult<()> {
        let mut hex: Vec<u8> = destination
            .data
            .iter()
            .copied()
            .filter(u8::is_ascii_hexdigit)
            .collect();
        if hex.len() & 1 == 1 {
            hex.pop();
        }
        self.objects_bytes = self.objects_bytes.saturating_add(hex.len() / 2);
        if self.objects_bytes > self.limits.objects_bytes
            || self.objects.len() >= self.limits.objects
        {
            return Err(memory_error());
        }
        let rawdata = unhexlify(&hex);
        let mut object = RtfObject {
            start: destination.start,
            rawdata_md5: md5_hex(&rawdata),
            ..Default::default()
        };
        // an object that isn't OLE 1.0 is still saved, raw
        if parse_ole_object(&rawdata, &mut object).is_err() {
            tracing::debug!("not an OLE 1.0 object");
        }
        object.rawdata = rawdata;
        self.objects.push(object);
        Ok(())
    }
}

fn unhexlify(hex: &[u8]) -> Vec<u8> {
    fn value(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => byte - b'A' + 10,
        }
    }
    hex.as_chunks::<2>()
        .0
        .iter()
        .map(|pair| value(pair[0]) << 4 | value(pair[1]))
        .collect()
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, ()> {
    let four = data.get(at..at + 4).ok_or(())?;
    Ok(u32::from_le_bytes([four[0], four[1], four[2], four[3]]))
}

/// `read_length_prefixed_string`, without the error's text, which `close_destination` swallows.
fn prefixed_string(data: &[u8], index: &mut usize) -> Result<ClassName, ()> {
    let length = u32_at(data, *index)? as usize;
    *index += 4;
    if length == 0 {
        return Ok(ClassName::EmptyStr);
    }
    let null_at = *index + length - 1;
    if *data.get(null_at).ok_or(())? != 0 {
        return Err(());
    }
    let text = data[*index..null_at].to_vec();
    *index += length;
    Ok(ClassName::Bytes(text))
}

/// `read_zero_terminated_string`. `guess_encoding` tries ASCII and then latin1, which always works.
fn zero_terminated(data: &[u8], index: &mut usize) -> Result<String, ()> {
    const STR_MAX_LEN: usize = 1024;
    let window_end = data.len().min(*index + STR_MAX_LEN);
    let window = data.get(*index..window_end).ok_or(())?;
    let end = window.iter().position(|&byte| byte == 0).ok_or(())?;
    let text = window[..end].iter().map(|&byte| byte as char).collect();
    *index += end + 1;
    Ok(text)
}

/// The `try` in `RtfObjParser.close_destination`, which leaves what it set before raising.
fn parse_ole_object(data: &[u8], object: &mut RtfObject) -> Result<(), ()> {
    let mut index = 4;
    u32_at(data, 0)?;
    let format_id = u32_at(data, index)?;
    index += 4;
    object.format_id = format_id;
    if format_id != 1 && format_id != 2 {
        return Err(());
    }
    let class_name = prefixed_string(data, &mut index)?;
    prefixed_string(data, &mut index)?;
    prefixed_string(data, &mut index)?;
    if format_id != 2 {
        // a linked object has no data, and md5 of None raises
        object.class_name = Some(class_name);
        return Err(());
    }
    let size = u32_at(data, index)?;
    index += 4;
    let end = index + size as usize;
    let Some(oledata) = data.get(index..end) else {
        return Err(());
    };
    object.oledata_size = Some(size);
    object.oledata = oledata.to_vec();
    object.oledata_md5 = md5_hex(oledata);
    object.is_ole = true;
    let oledata = object.oledata.clone();
    let lower = match &class_name {
        ClassName::Bytes(bytes) => Some(bytes.to_ascii_lowercase()),
        ClassName::EmptyStr => None,
    };
    object.class_name = Some(class_name);
    // '' .rstrip(b'\0') raises TypeError
    let lower = lower.ok_or(())?;
    let trimmed = lower
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(&lower[..0], |last| &lower[..=last]);
    if trimmed == b"package" {
        parse_package(&oledata, object)
    } else {
        if oledata.len() >= 1536 && has_magic(&oledata) {
            let ole = OleFile::open_bytes(Arc::new(oledata), 8).map_err(|_| ())?;
            let clsid = ole.root_clsid().to_owned();
            let upper = clsid.to_uppercase();
            object.clsid_desc = KNOWN_CLSIDS.iter().find(|row| row.0 == upper).map_or_else(
                || {
                    "unknown CLSID (please report at https://github.com/decalage2/oletools/issues)"
                        .to_owned()
                },
                |row| row.1.to_owned(),
            );
            object.clsid = Some(clsid);
        }
        Ok(())
    }
}

/// `OleNativeStream(bindata=..., package=True)`, then the type guess.
fn parse_package(data: &[u8], object: &mut RtfObject) -> Result<(), ()> {
    data.get(..2).ok_or(())?;
    let mut index = 2;
    let filename = zero_terminated(data, &mut index)?;
    let src_path = zero_terminated(data, &mut index)?;
    u32_at(data, index)?;
    u32_at(data, index + 4)?;
    index += 8;
    let temp_path = zero_terminated(data, &mut index)?;
    // a package with no room for its size is a link, whose data is None and md5 of that raises
    let size = u32_at(data, index)?;
    index += 4;
    let end = data.len().min(index.saturating_add(size as usize));
    let package = data.get(index..end).unwrap_or_default().to_vec();
    object.filename = filename;
    object.src_path = src_path;
    object.temp_path = temp_path;
    object.olepkgdata_md5 = md5_hex(&package);
    let package = Arc::new(package);
    object.ftype_name = ftguess::guess(&package, 8).map_err(|_| ())?.name;
    object.olepkgdata = Arc::try_unwrap(package).unwrap_or_default();
    object.is_package = true;
    Ok(())
}

/// `sanitize_filename`.
pub fn sanitize_filename(filename: &str) -> String {
    let base = filename.rsplit('/').next().unwrap_or_default();
    let base = strip(base);
    let mut sane: String = base
        .chars()
        .map(|c| {
            if is_word(c) || matches!(c, '.' | '-' | ' ') {
                c
            } else {
                '_'
            }
        })
        .collect();
    while sane.contains("..") {
        sane = sane.replace("..", ".");
    }
    while sane.contains("  ") {
        sane = sane.replace("  ", " ");
    }
    if filename.is_empty() {
        sane = "NONAME".to_owned();
    }
    sane.chars().take(200).collect()
}

/// `re_executable_extensions.match`.
fn is_executable_extension(extension: &str) -> bool {
    const EXTENSIONS: &[&[u8]] = &[
        b"bat", b"class", b"cmd", b"cpl", b"dll", b"exe", b"com", b"gadget", b"hta", b"inf",
        b"jar", b"js", b"jse", b"lnk", b"msc", b"msi", b"msp", b"pif", b"ps1", b"ps1xml", b"ps2",
        b"ps2xml", b"psc1", b"psc2", b"reg", b"scf", b"scr", b"sct", b"vb", b"vbe", b"vbs", b"ws",
        b"wsc", b"wsf", b"wsh",
    ];
    let Some(rest) = extension.strip_prefix('.') else {
        return false;
    };
    let word: Vec<u8> = rest
        .chars()
        .take_while(|&c| is_word(c))
        .map(crate::scanner::fold_char)
        .collect();
    EXTENSIONS.contains(&word.as_slice())
}

fn ole2link_urls(data: &[u8]) -> Vec<String> {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    let re = RE
        .get_or_init(|| BytesRegex::new(r"(?-u)(?:[\x20-\x7E]\x00){3,}").expect("a valid pattern"));
    let urls: BTreeSet<String> = re
        .find_iter(data)
        .map(|hit| {
            hit.as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| pair[0] as char)
                .collect::<String>()
        })
        .filter(|word| word.contains("http"))
        .collect();
    urls.into_iter().collect()
}

fn ole_column(object: &RtfObject) -> PyResult<String> {
    if !object.is_ole {
        return Ok("Not a well-formed OLE object".to_owned());
    }
    let class_name = object.class_name.as_ref().expect("an OLE object has one");
    let mut column = format!("format_id: {} (Embedded)\n", object.format_id);
    column.push_str(&format!("class name: {}\n", class_name.repr()));
    column.push_str(&format!(
        "data size: {}",
        object.oledata_size.unwrap_or_default()
    ));
    if object.is_package {
        column.push_str("\nOLE Package object:");
        column.push_str(&format!("\nFilename: {}", repr_str(&object.filename)));
        column.push_str(&format!("\nSource path: {}", repr_str(&object.src_path)));
        column.push_str(&format!("\nTemp path = {}", repr_str(&object.temp_path)));
        column.push_str(&format!("\nMD5 = {}", repr_str(&object.olepkgdata_md5)));
        let temp_extension = ftguess::splitext(&object.temp_path).1;
        let file_extension = ftguess::splitext(&object.filename).1;
        if temp_extension != file_extension {
            column.push_str("\nMODIFIED FILE EXTENSION");
        }
        if is_executable_extension(temp_extension) || is_executable_extension(file_extension) {
            column.push_str("\nEXECUTABLE FILE");
        }
        column.push_str(&format!("\nFile Type: {}", object.ftype_name));
    } else {
        column.push_str(&format!("\nMD5 = {}", repr_str(&object.oledata_md5)));
    }
    if let Some(clsid) = &object.clsid {
        column.push_str(&format!("\nCLSID: {clsid}\n{}", object.clsid_desc));
    }
    if matches!(class_name, ClassName::Bytes(bytes) if bytes == b"OLE2Link") {
        column.push_str(
            "\nPossibly an exploit for the OLE2Link vulnerability (VU#921560, CVE-2017-0199)\n",
        );
        let urls = ole2link_urls(&object.oledata);
        if !urls.is_empty() {
            column.push_str(&format!("URL extracted: {}", urls.join(", ")));
        }
    } else if class_name.lower()?.starts_with(b"equation.3") {
        column.push_str("\nPossibly an exploit for the Equation Editor vulnerability (VU#421280, CVE-2017-11882)");
    }
    Ok(column)
}

const WIDTHS: [usize; 3] = [3, 10, 63];

/// `TableStream.write`, which drops U+FFFD, for one row.
fn write_row(out: &mut String, row: [&str; 3]) {
    let columns: Vec<Vec<String>> = row
        .iter()
        .zip(WIDTHS)
        .map(|(cell, width)| {
            splitlines(cell)
                .iter()
                .flat_map(|line| textwrap::wrap(line, width))
                .collect()
        })
        .collect();
    let lines = columns.iter().map(Vec::len).max().unwrap_or(0);
    for line in 0..lines {
        for (index, column) in columns.iter().enumerate() {
            let text = column.get(line).map_or("", String::as_str);
            let padding = WIDTHS[index].saturating_sub(text.chars().count());
            out.extend(text.chars().filter(|&c| c != '\u{FFFD}'));
            out.extend(std::iter::repeat_n(' ', padding));
            if index < 2 {
                out.push('|');
            }
        }
        out.push('\n');
    }
}

const SEPARATOR: &str =
    "---+----------+---------------------------------------------------------------\n";

/// `process_file`. `name` is the file's name as the command was given it and `output_dir` where its
/// report says it saved, which is only ever text here.
pub fn process_file(name: &str, data: &[u8], output_dir: &str, limits: Limits) -> Report {
    let mut report = Report::default();
    if let Err(error) = run(name, data, output_dir, limits, &mut report) {
        report.raised = Some(error);
    }
    report
}

fn check_report(report: &Report, limits: Limits) -> PyResult<()> {
    if report.stdout.len() > limits.report_bytes {
        return Err(memory_error());
    }
    Ok(())
}

fn run(
    name: &str,
    data: &[u8],
    output_dir: &str,
    limits: Limits,
    report: &mut Report,
) -> PyResult<()> {
    let prefix = format!("{}/{}", output_dir, sanitize_filename(name));
    let out = &mut report.stdout;
    out.push_str(&"=".repeat(79));
    out.push('\n');
    out.push_str(&format!(
        "File: {} - size: {} bytes\n",
        repr_str(name),
        data.len()
    ));
    out.push_str(SEPARATOR);
    write_row(out, ["id", "index", "OLE Object"]);
    out.push_str(SEPARATOR);
    let mut parser = Parser::new(data, limits);
    let parsed = parser.parse();
    // the port's own limit keeps what it found, and raises after saving it. Python's exceptions stop here
    if parsed
        .as_ref()
        .is_err_and(|error| error.kind != "MemoryError")
    {
        return parsed;
    }
    let objects = std::mem::take(&mut parser.objects);
    for (index, object) in objects.iter().enumerate() {
        let column = ole_column(object)?;
        write_row(
            &mut report.stdout,
            [
                &index.to_string(),
                &format!("{:08X}h", object.start),
                &column,
            ],
        );
        report.stdout.push_str(SEPARATOR);
        check_report(report, limits)?;
    }
    let mut files_bytes = 0usize;
    for (index, object) in objects.iter().enumerate() {
        let (path, contents): (String, &[u8]) = if object.is_package {
            let out = &mut report.stdout;
            out.push_str(&format!(
                "Saving file from OLE Package in object #{index}:\n"
            ));
            out.push_str(&format!("  Filename = {}\n", repr_str(&object.filename)));
            out.push_str(&format!("  Source path = {}\n", repr_str(&object.src_path)));
            out.push_str(&format!("  Temp path = {}\n", repr_str(&object.temp_path)));
            let path = if object.filename.is_empty() {
                format!("{prefix}_object_{:08X}.noname", object.start)
            } else {
                format!("{prefix}_{}", sanitize_filename(&object.filename))
            };
            out.push_str(&format!("  saving to file {path}\n"));
            out.push_str(&format!("  md5 {}\n", object.olepkgdata_md5));
            (path, &object.olepkgdata)
        } else if object.is_ole {
            let class_name = object.class_name.as_ref().expect("an OLE object has one");
            let out = &mut report.stdout;
            out.push_str(&format!("Saving file embedded in OLE object #{index}:\n"));
            out.push_str(&format!("  format_id  = {}\n", object.format_id));
            out.push_str(&format!("  class name = {}\n", class_name.repr()));
            out.push_str(&format!(
                "  data size  = {}\n",
                object.oledata_size.unwrap_or_default()
            ));
            let lower = class_name.lower()?;
            let extension = if lower.starts_with(b"word") {
                "doc"
            } else if lower.starts_with(b"package") {
                "package"
            } else {
                "bin"
            };
            let path = format!("{prefix}_object_{:08X}.{extension}", object.start);
            report
                .stdout
                .push_str(&format!("  saving to file {path}\n"));
            report
                .stdout
                .push_str(&format!("  md5 {}\n", object.oledata_md5));
            (path, &object.oledata)
        } else {
            let out = &mut report.stdout;
            out.push_str(&format!("Saving raw data in object #{index}:\n"));
            let path = format!("{prefix}_object_{:08X}.raw", object.start);
            out.push_str(&format!("  saving object to file {path}\n"));
            out.push_str(&format!("  md5 {}\n", object.rawdata_md5));
            (path, &object.rawdata)
        };
        check_report(report, limits)?;
        let file_name = path.rsplit('/').next().unwrap_or_default().to_owned();
        // what open(fname, 'wb') raises on a name too long for a filesystem
        if file_name.len() > 255 {
            return Err(PyErr::new(
                "OSError",
                format!("[Errno 36] File name too long: {}", repr_str(&path)),
            ));
        }
        files_bytes = files_bytes.saturating_add(contents.len());
        let existing = report
            .files
            .iter()
            .position(|(known, _)| *known == file_name);
        if files_bytes > limits.files_bytes
            || (existing.is_none() && report.files.len() >= limits.files)
        {
            return Err(memory_error());
        }
        match existing {
            Some(at) => report.files[at].1 = contents.to_vec(),
            None => report.files.push((file_name, contents.to_vec())),
        }
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_with_no_objects_only_has_the_table_head() {
        let report = process_file("a.rtf", b"{\\rtf1 text}", "/o", Limits::NONE);
        assert!(report.raised.is_none());
        assert!(report.files.is_empty());
        assert!(report.stdout.starts_with(&"=".repeat(79)));
        assert!(report.stdout.contains("File: 'a.rtf' - size: 12 bytes\n"));
    }

    #[test]
    fn bin_at_the_end_raises_as_python_does() {
        let report = process_file("a.rtf", b"{\\rtf1 \\bin", "/o", Limits::NONE);
        assert_eq!(report.raised.expect("it raises").kind, "TypeError");
    }

    #[test]
    fn a_raw_object_is_saved_under_its_offset() {
        let report = process_file(
            "a.rtf",
            b"{\\object{\\objdata 41 42 43}}",
            "/o",
            Limits::NONE,
        );
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].0, format!("a.rtf_object_{:08X}.raw", 17));
        assert_eq!(report.files[0].1, b"ABC");
    }

    #[test]
    fn sanitize_is_pythons() {
        assert_eq!(sanitize_filename("/a/b c..d$e"), "b c.d_e");
        assert_eq!(sanitize_filename(""), "NONAME");
    }

    #[test]
    fn the_limits_stop_saving() {
        let limits = Limits {
            files: 1,
            ..Limits::NONE
        };
        let report = process_file("a.rtf", b"{\\objdata 41}{\\objdata 42}", "/o", limits);
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.raised.expect("it stops").kind, "MemoryError");
    }
}
