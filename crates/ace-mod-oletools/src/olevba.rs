//! olevba's `VBA_Parser` with `relaxed=True`, as ace3's module and the library diff call it.
//!
//! Three things it calls aren't all here. XLMMacroDeobfuscator isn't ported until PLAN.md 4.12, so a
//! macro sheet beside VBA gives the `XLM macro` keyword without the text olevba gets from it. pcodedmp
//! is ported (`pcode.rs`), because stomping is decided on its whole output. ftguess only answers
//! whether a file is Excel.

use std::collections::HashSet;
use std::sync::Arc;

use ace_results::bytes::{Bytes, TextOrBytes};

use crate::codepage::Decoder;
use crate::ftguess::{self, FileType};
use crate::ole::{self, MAGIC, OleFile, STGTY_STREAM};
use crate::pcode::PCodeDumper;
use crate::ppt;
use crate::py::{PyErr, PyResult, is_space, memory_error, splitlines, strip};
use crate::pyemail;
use crate::pyxml;
use crate::pyzip::{self, ZipFile};
use crate::scanner::{self, ScanResult};
use crate::vba;

/// The most all of a file's macros may add up to. Past it extraction raises MemoryError.
pub const MAX_MACROS: usize = 64 * 1024 * 1024;
/// How many macros a file may have, for the same reason: each becomes a file in the alert.
pub const MAX_MACRO_FILES: usize = 4096;
const MAX_MSO: usize = 256 * 1024 * 1024;
const RECURSION_LIMIT: usize = 1000;
const NS_W: &str = "{http://schemas.microsoft.com/office/word/2003/wordml}";
const NS_PKG: &str = "{http://schemas.microsoft.com/office/2006/xmlPackage}";

/// `(file_name, stream_path, vba_filename, vba_code)`.
#[derive(Debug, Clone)]
pub struct Macro {
    pub file_name: Option<TextOrBytes>,
    pub stream_path: Option<String>,
    pub vba_filename: Option<TextOrBytes>,
    pub code: Option<String>,
}

fn text(value: &str) -> TextOrBytes {
    TextOrBytes::Text(value.to_owned())
}

fn name_text(name: Option<&TextOrBytes>) -> String {
    match name {
        None => "None".to_owned(),
        Some(TextOrBytes::Text(text)) => text.clone(),
        Some(TextOrBytes::Bytes(bytes)) => String::from_utf8_lossy(bytes.as_slice()).into_owned(),
    }
}

fn file_open_error(message: &str) -> PyErr {
    PyErr::new("FileOpenError", format!("Failed to open file {message}"))
}

/// `MsoExtractionError`'s constructor calls itself, so raising one is a RecursionError.
fn mso_error() -> PyErr {
    PyErr::new("RecursionError", "maximum recursion depth exceeded")
}

#[derive(Debug)]
pub struct VbaParser {
    pub filename: Option<TextOrBytes>,
    /// Whether this came from a file rather than bytes: only those get p-code and XLM.
    file_on_disk: bool,
    data: Arc<Vec<u8>>,
    pub kind: Option<&'static str>,
    ole_file: Option<OleFile>,
    subfiles: Vec<VbaParser>,
    file_type: FileType,
    vba_projects: Option<Vec<(String, String, String)>>,
    contains_vba: Option<bool>,
    contains_xlm: bool,
    vba_code_all_modules: Option<String>,
    modules: Option<Vec<Macro>>,
    modules_bytes: usize,
    pcode_output: Option<String>,
    stomping: Option<bool>,
    analysis: Option<Vec<ScanResult>>,
    depth: usize,
}

impl VbaParser {
    /// `VBA_Parser(path)` where the file's already read.
    pub fn open(name: &str, data: Vec<u8>) -> PyResult<VbaParser> {
        // <module>, main, run, then this
        VbaParser::new(Some(text(name)), Arc::new(data), true, 3)
    }

    fn new(
        filename: Option<TextOrBytes>,
        data: Arc<Vec<u8>>,
        on_disk: bool,
        depth: usize,
    ) -> PyResult<VbaParser> {
        if depth + 1 >= RECURSION_LIMIT {
            return Err(mso_error());
        }
        let file_type = ftguess::guess(&data, depth + 3)?;
        let mut parser = VbaParser {
            filename,
            file_on_disk: on_disk,
            data: Arc::clone(&data),
            kind: None,
            ole_file: None,
            subfiles: Vec::new(),
            file_type,
            vba_projects: None,
            contains_vba: None,
            contains_xlm: false,
            vba_code_all_modules: None,
            modules: None,
            modules_bytes: 0,
            pcode_output: None,
            stomping: None,
            analysis: None,
            depth,
        };
        if ole::has_magic(&data) {
            parser.open_ole()?;
            parser.open_ppt()?;
        }
        if parser.kind.is_none() && pyzip::is_zipfile(&data) {
            parser.open_openxml()?;
        }
        if parser.kind.is_none() {
            parser.open_others()?;
        }
        if parser.kind.is_none() {
            return Err(file_open_error(&format!(
                "{} is not a supported file type, cannot extract VBA Macros.",
                name_text(parser.filename.as_ref())
            )));
        }
        Ok(parser)
    }

    /// `except (IOError, TypeError, ValueError)`: anything else leaves the constructor.
    fn open_ole(&mut self) -> PyResult<()> {
        match OleFile::open(Arc::clone(&self.data), self.depth + 2) {
            Ok(ole) => {
                self.ole_file = Some(ole);
                self.kind = Some("OLE");
                Ok(())
            }
            Err(error)
                if error.is_os_error() || error.is_value_error() || error.kind == "TypeError" =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn open_ppt(&mut self) -> PyResult<()> {
        let Some(mut ole) = self.ole_file.take() else {
            // PptParser(None) makes an empty OleFileIO, whose listdir reads its absent root
            return Err(PyErr::new(
                "AttributeError",
                "'NoneType' object has no attribute 'name'",
            ));
        };
        let depth = self.depth;
        let subfiles = &mut self.subfiles;
        let result = ppt::iter_vba_data(&mut ole, |data| {
            subfiles.push(VbaParser::new(None, Arc::new(data), false, depth + 2)?);
            Ok(())
        });
        match result {
            Ok(()) => {
                self.kind = Some("PPT");
                Ok(())
            }
            Err(error) if error.kind == "PptUnexpectedData" || error.is_value_error() => {
                self.ole_file = Some(ole);
                Ok(())
            }
            Err(error) => {
                self.ole_file = Some(ole);
                Err(error)
            }
        }
    }

    /// `append_subfile`, with a relaxed parser's FileOpenError swallowed.
    fn append_subfile(&mut self, filename: Option<TextOrBytes>, data: Vec<u8>) -> PyResult<()> {
        match VbaParser::new(filename, Arc::new(data), false, self.depth + 2) {
            Ok(subfile) => {
                self.subfiles.push(subfile);
                Ok(())
            }
            Err(error) if error.kind == "FileOpenError" => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn open_openxml(&mut self) -> PyResult<()> {
        match self.read_openxml() {
            Ok(()) => {
                self.kind = Some("OpenXML");
                Ok(())
            }
            // except (RuntimeError, BadZipfile, LargeZipFile, IOError)
            Err(error)
                if error.is_os_error()
                    || matches!(
                        error.kind.as_str(),
                        "RuntimeError"
                            | "NotImplementedError"
                            | "RecursionError"
                            | "BadZipFile"
                            | "LargeZipFile"
                    ) =>
            {
                Ok(())
            }
            // a file on disk gives OSError for what seeking a BytesIO before its start gives ValueError
            Err(error) if self.file_on_disk && error.message.starts_with("negative seek value") => {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn read_openxml(&mut self) -> PyResult<()> {
        let data = Arc::clone(&self.data);
        let zip = ZipFile::new(&data)?;
        let names: Vec<String> = zip.namelist().into_iter().map(str::to_owned).collect();
        for name in names {
            let magic = zip.open_read(&name, Some(8))?;
            if magic == MAGIC {
                let contents = zip.open_read(&name, None)?;
                self.append_subfile(Some(text(&name)), contents)?;
            }
        }
        Ok(())
    }

    fn open_others(&mut self) -> PyResult<()> {
        let data = Arc::clone(&self.data);
        if memchr::memmem::find(
            &data,
            b"http://schemas.microsoft.com/office/word/2003/wordml",
        )
        .is_some()
        {
            // every exception but the relaxed ones is logged
            if self.open_word2003xml(&data).is_ok() {
                self.kind = Some("Word2003_XML");
            }
        }
        if memchr::memmem::find(
            &data,
            b"http://schemas.microsoft.com/office/2006/xmlPackage",
        )
        .is_some()
            && self.open_flatopc(&data).is_ok()
        {
            self.kind = Some("FlatOPC_XML");
        }
        let lower = data.to_ascii_lowercase();
        if self.kind.is_none() {
            let mime = memchr::memmem::find(&lower, b"mime");
            let version = memchr::memmem::find(&lower, b"version");
            if let (Some(mime), Some(version)) = (mime, version)
                && memchr::memmem::find(&lower, b"multipart").is_some()
                && mime.abs_diff(version) < 20
            {
                self.open_mht(&data)?;
            }
        }
        if data.starts_with(b"{\\rt") {
            return Err(file_open_error(&format!(
                "{} is RTF, which cannot contain VBA Macros. Please use rtfobj to analyse it.",
                name_text(self.filename.as_ref())
            )));
        }
        if data.starts_with(b"ID") {
            self.kind = Some("SLK");
        }
        if self.kind.is_none() && !data.contains(&0) {
            self.vba_code_all_modules = Some(String::from_utf8_lossy(&data).into_owned());
            self.contains_vba = Some(true);
            self.kind = Some("Text");
        }
        Ok(())
    }

    fn open_word2003xml(&mut self, data: &[u8]) -> PyResult<()> {
        let root = pyxml::fromstring(data)?;
        let attribute = format!("{NS_W}name");
        for bindata in root.iter_tag(&format!("{NS_W}binData")) {
            let name = bindata.get(&attribute).unwrap_or("noname.mso").to_owned();
            let mso = a2b_base64(bindata.text.as_deref())?;
            if mso.starts_with(b"ActiveMime") {
                let ole_data = mso_file_extract(&mso)?;
                self.append_subfile(Some(text(&name)), ole_data)?;
            }
        }
        Ok(())
    }

    fn open_flatopc(&mut self, data: &[u8]) -> PyResult<()> {
        let root = pyxml::fromstring(data)?;
        let binary_tag = format!("{NS_PKG}binaryData");
        let (name_key, type_key) = (format!("{NS_PKG}name"), format!("{NS_PKG}contentType"));
        for part in root.iter_tag(&format!("{NS_PKG}part")) {
            let name = part.get(&name_key).unwrap_or("unknown").to_owned();
            if part.get(&type_key) == Some("application/vnd.ms-office.vbaProject") {
                for bindata in part.find_children(&binary_tag) {
                    let ole_data = a2b_base64(bindata.text.as_deref())?;
                    self.append_subfile(Some(text(&name)), ole_data)?;
                }
            }
        }
        Ok(())
    }

    fn open_mht(&mut self, data: &[u8]) -> PyResult<()> {
        let start = data
            .iter()
            .position(|byte| !matches!(byte, b'\r' | b'\n' | b'\t' | b' '))
            .unwrap_or(data.len());
        let mut stripped = &data[start..];
        let mime = memchr::memmem::find(stripped, b"MIME");
        let content = memchr::memmem::find(stripped, b"Content");
        match (mime, content) {
            (Some(mime), Some(content)) if mime <= content => stripped = &stripped[mime..],
            (_, Some(content)) => stripped = &stripped[content..],
            _ => {}
        }
        let (parts, error) = pyemail::parts_until_error(stripped);
        for part in parts {
            if let Some(payload) = part.payload
                && payload.starts_with(b"ActiveMime")
            {
                let ole_data = match mso_file_extract(&payload) {
                    Ok(ole_data) => ole_data,
                    // every exception that isn't olevba's own is logged, and type stays None
                    Err(_) => return Ok(()),
                };
                match self.append_subfile(part.filename, ole_data) {
                    Ok(()) => {}
                    Err(error) if error.kind == "FileOpenError" => return Err(error),
                    Err(_) => return Ok(()),
                }
            }
        }
        if error.is_none() {
            self.kind = Some("MHTML");
        }
        Ok(())
    }

    /// `find_vba_projects`. None when the file isn't OLE or PPT.
    fn find_vba_projects(&mut self) -> Option<Vec<(String, String, String)>> {
        if self.ole_file.is_none() && self.kind != Some("PPT") {
            return None;
        }
        if let Some(projects) = &self.vba_projects {
            return Some(projects.clone());
        }
        let mut projects = Vec::new();
        if self.kind == Some("PPT") {
            for subfile in &mut self.subfiles {
                // a list extended with None raises TypeError, which only happens to a nested parser
                projects.extend(subfile.find_vba_projects().unwrap_or_default());
            }
            self.vba_projects = Some(projects.clone());
            return Some(projects);
        }
        let ole = self.ole_file.as_ref().expect("checked");
        for storage in ole.listdir(false, true) {
            let last = storage.last().expect("a path has a name");
            if last.to_uppercase() != "VBA" {
                continue;
            }
            let mut root = storage[..storage.len() - 1].join("/");
            if !root.is_empty() {
                root.push('/');
            }
            let check = |path: &str| ole.get_type(path) == Some(STGTY_STREAM);
            let project = format!("{root}PROJECT");
            let dir = format!("{root}VBA/dir");
            if check(&project) && check(&format!("{root}VBA/_VBA_PROJECT")) && check(&dir) {
                projects.push((root, project, dir));
            }
        }
        self.vba_projects = Some(projects.clone());
        Some(projects)
    }

    /// `detect_vba_macros`.
    pub fn detect_vba_macros(&mut self) -> PyResult<bool> {
        if let Some(known) = self.contains_vba {
            return Ok(known);
        }
        if self.ole_file.is_none() {
            for subfile in &mut self.subfiles {
                if subfile.detect_vba_macros()? {
                    self.contains_vba = Some(true);
                    return Ok(true);
                }
            }
            self.contains_vba = Some(false);
            return Ok(false);
        }
        let projects = self.find_vba_projects().unwrap_or_default();
        let mut contains = !projects.is_empty();
        // also in any stream, orphans included
        let ole = self.ole_file.as_mut().expect("checked");
        for sid in 0..ole.direntries.len() {
            let (entry_type, _, start, size) = ole.load_entry(sid)?;
            if entry_type == STGTY_STREAM {
                let data = ole.open_chain(start, size)?;
                if memchr::memmem::find(&data, b"Attribut\x00").is_some() {
                    contains = true;
                }
            }
        }
        self.contains_vba = Some(contains);
        Ok(contains)
    }

    /// Whether a workbook holds a macro sheet, standing in for what XLMMacroDeobfuscator and
    /// plugin_biff say until 4.12. Only an Excel file on disk gets this far in olevba.
    fn detect_xlm(&mut self) -> PyResult<bool> {
        if self.contains_xlm || !self.file_type.is_excel || !self.file_on_disk {
            return Ok(self.contains_xlm);
        }
        self.contains_xlm = crate::xlm::has_macro_sheet(&self.data, self.ole_file.as_mut());
        Ok(self.contains_xlm)
    }

    fn push_macro(&mut self, item: Macro) -> PyResult<()> {
        self.modules_bytes += item.code.as_ref().map_or(0, String::len);
        let modules = self.modules.get_or_insert_with(Vec::new);
        if self.modules_bytes > MAX_MACROS || modules.len() >= MAX_MACRO_FILES {
            return Err(memory_error());
        }
        modules.push(item);
        Ok(())
    }

    /// `extract_all_macros`. Python's generator yields into the list as it goes, so stomping is
    /// decided on what's there before the p-code, and an exception leaves the list as it was.
    pub fn extract_all_macros(&mut self) -> PyResult<&[Macro]> {
        if self.modules.is_none() {
            self.modules = Some(Vec::new());
            self.extract_macros()?;
        }
        Ok(self.modules.as_deref().unwrap_or_default())
    }

    /// What `extract_all_macros` holds now, after a limit stopped it.
    pub fn macros_so_far(&self) -> &[Macro] {
        self.modules.as_deref().unwrap_or_default()
    }

    fn extract_macros(&mut self) -> PyResult<()> {
        if self.ole_file.is_none() {
            if self.kind == Some("Text") {
                let code = self.vba_code_all_modules.clone();
                let item = Macro {
                    file_name: self.filename.clone(),
                    stream_path: Some(String::new()),
                    vba_filename: self.filename.clone(),
                    code,
                };
                return self.push_macro(item);
            }
            if self.kind == Some("SLK") {
                return Ok(());
            }
            let mut subfiles = std::mem::take(&mut self.subfiles);
            let result = (|| {
                for subfile in &mut subfiles {
                    subfile.modules = Some(Vec::new());
                    subfile.modules_bytes = self.modules_bytes;
                    let extracted = subfile.extract_macros();
                    let items = subfile.modules.take().unwrap_or_default();
                    subfile.modules = None;
                    for item in items {
                        self.push_macro(item)?;
                    }
                    extracted?;
                }
                Ok(())
            })();
            self.subfiles = subfiles;
            return result;
        }
        let projects = self.find_vba_projects().unwrap_or_default();
        let filename = self.filename.clone();
        let mut ids = HashSet::new();
        for (root, project, dir) in &projects {
            let mut ole = self.ole_file.take().expect("checked");
            let mut produced = Vec::new();
            // a project's exception is logged, and what it yielded stays
            let extracted = vba::extract_vba(&mut ole, root, project, dir, |ole, module| {
                ids.insert(ole.find(&module.code_path)?);
                produced.push(module);
                Ok(())
            });
            if let Err(error) = extracted {
                tracing::debug!(%error, "error in _extract_vba");
            }
            self.ole_file = Some(ole);
            for module in produced {
                self.push_macro(Macro {
                    file_name: filename.clone(),
                    stream_path: Some(module.code_path),
                    vba_filename: module.filename.map(TextOrBytes::Text),
                    code: module.code,
                })?;
            }
        }
        let sids = self.ole_file.as_ref().expect("checked").direntries.len();
        for sid in 0..sids {
            if ids.contains(&sid) {
                continue;
            }
            let ole = self.ole_file.as_mut().expect("checked");
            let (entry_type, name, start, size) = ole.load_entry(sid)?;
            if entry_type != STGTY_STREAM {
                continue;
            }
            let data = ole.open_chain(start, size)?;
            for hit in attribut_matches(&data) {
                let code = if hit < 3 {
                    let from = data.len().saturating_sub(3 - hit);
                    &data[from..]
                } else {
                    &data[hit - 3..]
                };
                if let Ok(code) = vba::decompress_stream(code) {
                    self.push_macro(Macro {
                        file_name: filename.clone(),
                        stream_path: Some(name.clone()),
                        vba_filename: Some(text(&name)),
                        code: Some(Decoder::cp1252().decode(&code)),
                    })?;
                }
            }
        }
        if self.detect_vba_stomping()? {
            let mut code = String::new();
            for line in splitlines(self.pcode_output.as_deref().unwrap_or_default()) {
                code.push_str("' ");
                code.push_str(line);
                code.push('\n');
            }
            self.push_macro(Macro {
                file_name: Some(text("VBA P-code")),
                stream_path: Some("VBA P-code".to_owned()),
                vba_filename: Some(text("VBA_P-code.txt")),
                code: Some(code),
            })?;
        }
        Ok(())
    }

    /// `extract_pcode`: `pcodedmp.processFile` on the file olevba was given, with its stderr in the
    /// same buffer. It rereads the file, which comes to these same parsers.
    fn extract_pcode(&mut self) {
        if matches!(self.kind, Some("SLK" | "Text")) {
            self.pcode_output = Some(String::new());
            return;
        }
        if self.pcode_output.is_some() {
            return;
        }
        let mut dumper = PCodeDumper::new(true, true);
        dumper.print_line(&format!(
            "Processing file: {}",
            name_text(self.filename.as_ref())
        ));
        process_parser_projects(self, &mut dumper);
        self.pcode_output = Some(dumper.into_output().0);
    }

    /// `detect_vba_stomping`.
    fn detect_vba_stomping(&mut self) -> PyResult<bool> {
        if let Some(known) = self.stomping {
            return Ok(known);
        }
        if matches!(self.kind, Some("SLK" | "Text")) || !self.file_on_disk {
            self.stomping = Some(false);
            return Ok(false);
        }
        self.extract_pcode();
        let keywords = pcode_keywords(self.pcode_output.as_deref().unwrap_or_default())?;
        // get_vba_code_all_modules, with what extract_all_macros holds at this moment
        self.stomping = Some(false);
        if self.modules.is_none() {
            self.extract_all_macros()?;
        }
        let mut all = String::new();
        for code in self
            .modules
            .iter()
            .flatten()
            .filter_map(|item| item.code.as_ref())
        {
            all.push_str(code);
            all.push('\n');
        }
        let stomped = keywords
            .iter()
            .any(|keyword| !all.contains(keyword.as_str()));
        self.stomping = Some(stomped);
        Ok(stomped)
    }

    /// `extract_form_strings`, appending to what the scanner reads.
    fn extract_form_strings(&mut self, all: &mut String) -> PyResult<()> {
        if self.ole_file.is_none() {
            if self.kind == Some("Text") {
                return Ok(());
            }
            for subfile in &mut self.subfiles {
                subfile.extract_form_strings(all)?;
            }
            return Ok(());
        }
        let ole = self.ole_file.as_mut().expect("checked");
        let mut forms = Vec::new();
        for storage in ole.listdir(false, true) {
            let with = |name: &str| {
                let mut path = storage.clone();
                path.push(name.to_owned());
                path
            };
            if ole.get_type_parts(&with("o")) == Some(STGTY_STREAM)
                && ole.get_type_parts(&with("f")) == Some(STGTY_STREAM)
            {
                forms.push(with("o"));
            }
        }
        for form in forms {
            let data = ole.read_stream_parts(&form)?;
            for run in printable_runs(&data) {
                let found = String::from_utf8_lossy(run);
                if found != "Tahoma" {
                    all.push_str(&found);
                    all.push('\n');
                }
                if all.len() > MAX_MACROS * 2 {
                    return Err(memory_error());
                }
            }
        }
        Ok(())
    }

    /// `analyze_macros(show_decoded_strings=True, deobfuscate=False)`.
    pub fn analyze_macros(&mut self) -> PyResult<Vec<ScanResult>> {
        if !self.detect_vba_macros()? {
            self.detect_xlm()?;
            if !self.contains_xlm {
                return Ok(Vec::new());
            }
        } else {
            self.detect_xlm()?;
        }
        if let Some(results) = &self.analysis {
            return Ok(results.clone());
        }
        let all = match self.vba_code_all_modules.clone() {
            Some(code) => code,
            None => {
                self.extract_all_macros()?;
                let mut all = String::new();
                for code in self
                    .modules
                    .iter()
                    .flatten()
                    .filter_map(|item| item.code.as_ref())
                {
                    all.push_str(code);
                    all.push('\n');
                }
                self.extract_form_strings(&mut all)?;
                all
            }
        };
        let mut results = scanner::scan(&all);
        self.vba_code_all_modules = Some(all);
        if self.detect_vba_stomping()? {
            results.push((
                "Suspicious".to_owned(),
                "VBA Stomping".to_owned(),
                "VBA Stomping was detected: the VBA source code and P-code are different, this may have been used to hide malicious code"
                    .to_owned(),
            ));
        }
        if self.contains_xlm {
            results.push((
                "Suspicious".to_owned(),
                "XLM macro".to_owned(),
                "XLM macro found. It may contain malicious code".to_owned(),
            ));
        }
        self.analysis = Some(results.clone());
        Ok(results)
    }
}

/// `processFile`'s body after its constructor, on the parser that's already open.
fn process_parser_projects(parser: &mut VbaParser, dumper: &mut PCodeDumper) {
    if parser.ole_file.is_none() {
        for subfile in &mut parser.subfiles {
            process_project(subfile, dumper);
        }
    } else {
        process_project(parser, dumper);
    }
}

fn process_project(parser: &mut VbaParser, dumper: &mut PCodeDumper) {
    let Some(projects) = parser.find_vba_projects() else {
        return;
    };
    match parser.ole_file.as_mut() {
        Some(ole) => dumper.process_project(ole, &projects),
        // a nested PPT's parser has no ole_file, which the first project's dir read trips on
        None if !projects.is_empty() => {
            dumper.print_line(&"=".repeat(79));
            dumper.print_error("'NoneType' object has no attribute 'openstream'");
        }
        None => {}
    }
}

/// `pcodedmp.processFile`, for the module's output and the library diff of pcodedmp.
pub fn pcodedmp_process_file(name: &str, data: Vec<u8>, disasm_only: bool) -> (String, String) {
    let mut dumper = PCodeDumper::new(disasm_only, false);
    dumper.print_line(&format!("Processing file: {name}"));
    match VbaParser::open(name, data) {
        Ok(mut parser) => process_parser_projects(&mut parser, &mut dumper),
        Err(error) => dumper.print_error(&error.message),
    }
    dumper.into_output()
}

/// `re.finditer(b'\x00Attribut[^e]', data, re.IGNORECASE)`: where each match starts.
fn attribut_matches(data: &[u8]) -> Vec<usize> {
    const WORD: &[u8] = b"attribut";
    let mut hits = Vec::new();
    let mut from = 0;
    while let Some(found) = memchr::memchr(0, &data[from..]) {
        let at = from + found;
        from = at + 1;
        let Some(following) = data.get(at + 1..at + 1 + WORD.len()) else {
            break;
        };
        if following.eq_ignore_ascii_case(WORD)
            && let Some(&next) = data.get(at + 1 + WORD.len())
            && !next.eq_ignore_ascii_case(&b'e')
        {
            hits.push(at);
            from = at + 2 + WORD.len();
        }
    }
    hits
}

/// `re_printable_string.finditer`: runs of 5 or more of `[\t\r\n\x20-\xFF]`.
fn printable_runs(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    data.split(|&byte| !(matches!(byte, b'\t' | b'\r' | b'\n') || byte >= 0x20))
        .filter(|run| run.len() >= 5)
}

/// What `detect_vba_stomping` pulls from the p-code, with the exceptions its parsing can raise.
fn pcode_keywords(output: &str) -> PyResult<Vec<String>> {
    let mut keywords = Vec::new();
    let index_error = || PyErr::new("IndexError", "list index out of range");
    for line in splitlines(output) {
        if !line.starts_with('\t') {
            continue;
        }
        let tokens = crate::py::split_whitespace_once(line);
        let mnemonic = *tokens.first().ok_or_else(index_error)?;
        let args = tokens.get(1).map_or("", |args| strip(args));
        if matches!(
            mnemonic,
            "ArgsCall" | "ArgsLd" | "St" | "Ld" | "MemSt" | "Label"
        ) {
            let args = args.strip_prefix("(Call) ").unwrap_or(args);
            let name = args
                .split(is_space)
                .find(|part| !part.is_empty())
                .ok_or_else(index_error)?;
            if !name.starts_with("id_") {
                keywords.push(name.to_owned());
            }
        }
        if mnemonic == "LitStr" {
            let parts = crate::py::split_whitespace_once(args);
            let mut literal = (*parts.get(1).ok_or_else(index_error)?).to_owned();
            if literal.chars().count() >= 2 {
                if !(literal.starts_with('"') && literal.ends_with('"')) {
                    return Err(PyErr::new("AssertionError", ""));
                }
                let inner = &literal[1..literal.len() - 1];
                literal = format!("\"{}\"", inner.replace('"', "\"\""));
            }
            keywords.push(literal);
        }
    }
    Ok(keywords)
}

/// `mso_file_extract`.
fn mso_file_extract(data: &[u8]) -> PyResult<Vec<u8>> {
    let Some(pair) = data.get(0x1E..0x20) else {
        return Err(mso_error());
    };
    let first = usize::from(u16::from_le_bytes([pair[0], pair[1]])) + 46;
    for start in [first, 0x32, 0x22A] {
        match pyzip::zlib_decompress(data.get(start..).unwrap_or_default(), true, MAX_MSO) {
            Ok(out) => return Ok(out),
            Err(error) if error.kind == "error" => {}
            Err(error) => return Err(error),
        }
    }
    // a str pattern on bytes, in olevba's search for other zlib blocks
    Err(PyErr::new(
        "TypeError",
        "cannot use a string pattern on a bytes-like object",
    ))
}

/// `binascii.a2b_base64` of an element's text, not strict. Its errors are all logged the same way.
fn a2b_base64(input: Option<&str>) -> PyResult<Vec<u8>> {
    let Some(input) = input else {
        return Err(PyErr::new(
            "TypeError",
            "a bytes-like object is required, not 'NoneType'",
        ));
    };
    if !input.is_ascii() {
        return Err(PyErr::new(
            "ValueError",
            "string argument should contain only ASCII characters",
        ));
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut quad = 0;
    let mut pads = 0;
    let mut left = 0u32;
    for byte in input.bytes() {
        if byte == b'=' {
            pads += 1;
            if quad >= 2 && quad + pads >= 4 {
                return Ok(out);
            }
            continue;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        pads = 0;
        match quad {
            0 => {
                quad = 1;
                left = u32::from(value);
            }
            1 => {
                quad = 2;
                out.push(((left << 2) | u32::from(value >> 4)) as u8);
                left = u32::from(value & 0x0F);
            }
            2 => {
                quad = 3;
                out.push(((left << 4) | u32::from(value >> 2)) as u8);
                left = u32::from(value & 0x03);
            }
            _ => {
                quad = 0;
                out.push(((left << 6) | u32::from(value)) as u8);
                left = 0;
            }
        }
    }
    if quad != 0 {
        return Err(PyErr::new("Error", "Incorrect padding"));
    }
    Ok(out)
}

/// What `TextOrBytes` holds of a name that's bytes, for a caller that needs text.
pub fn name_or_empty(name: &Option<TextOrBytes>) -> TextOrBytes {
    name.clone()
        .unwrap_or_else(|| TextOrBytes::Bytes(Bytes::new(Vec::new())))
}
