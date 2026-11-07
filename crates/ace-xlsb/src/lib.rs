//! What XLMMacroDeobfuscator reads of an .xlsb workbook: the parts of pyxlsb2 that `xlsb_wrapper.py`
//! calls, and that wrapper's data access. It holds no zip or XML reader; a [`Package`] supplies both.
//!
//! Output, refusal and exception messages follow pyxlsb2 under Python 3.14, including a truncated
//! file's None fields. Each limit below raises MemoryError where Python would run out of memory.

use std::fmt;

use indexmap::IndexMap;

mod funcs;
mod ptg;
mod pyfmt;
mod reader;

pub use pyfmt::float_str;

use ptg::{Ctx, MAX_TEXT};
use pyfmt::{
    LIST_RANGE, NOT_SUBSCRIPTABLE, bytes_repr, fmt_opt, index_error, memory_error, none_attr,
    py_lower, type_error,
};
use reader::{ExternSheets, Rec, RecordReader};

/// Kept cells across one `load_cells`.
const MAX_CELLS: usize = 8_000_000;
/// Text of the kept cells of one `load_cells`, and of a workbook's name formulas together.
const MAX_TOTAL_TEXT: usize = 1 << 32;
/// Records a workbook keeps. A record can be as small as 2 bytes of file.
const MAX_SHEETS: usize = 8_000_000;
const MAX_NAMES: usize = 16_000_000;
const MAX_SHARED_STRINGS: usize = 64_000_000;
/// The frames above XLSBWrapper(...) or load_cells(...) when the caller doesn't say.
pub const DEFAULT_CALLER_FRAMES: usize = 2;
/// XLSBWrapper.__init__, open_workbook, Workbook.__init__, _parse, Formula.stringify.
const OPEN_FRAMES: usize = 5;
/// load_cells, Formula.stringify.
const LOAD_FRAMES: usize = 2;
const ROW_CAP: u64 = 1_048_576;
const COLUMN_CAP: u32 = 16_384;

const WORKSHEET_TYPE: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet";
const MACROSHEET_TYPE: &str = "http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet";
const INTL_MACROSHEET_TYPE: &str =
    "http://schemas.microsoft.com/office/2006/relationships/xlIntlMacrosheet";

/// A Python exception as data: its type name and `str(exc)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XlError {
    pub kind: String,
    pub message: String,
}

impl XlError {
    pub fn new(kind: &str, message: impl Into<String>) -> Self {
        XlError {
            kind: kind.to_string(),
            message: message.into(),
        }
    }

    fn pass_timeout() -> Self {
        XlError::new("PassTimeout", "the pass deadline expired")
    }
}

impl fmt::Display for XlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            f.write_str(&self.kind)
        } else {
            write!(f, "{}: {}", self.kind, self.message)
        }
    }
}

impl std::error::Error for XlError {}

/// Python's `cell.value`.
#[derive(Clone, Debug, PartialEq)]
pub enum CellValue {
    None,
    /// str: CELL_ST, FMLA_STRING, or a shared string.
    Text(String),
    /// float: CELL_RK, CELL_REAL, FMLA_NUM. Can be nan or inf; [`float_str`] gives its str().
    Float(f64),
    /// int: a CELL_ISST index outside the shared strings.
    Int(i64),
    /// bool: CELL_BOOL, FMLA_BOOL.
    Bool(bool),
    /// A pyxlsb2 ErrorValue: CELL_ERROR, FMLA_ERROR. Holds its str(), such as `#ERR!7` or `#ERR!None`.
    Error(String),
}

impl CellValue {
    /// `'{}'.format(value)`.
    pub fn py_str(&self) -> String {
        match self {
            CellValue::None => "None".to_string(),
            CellValue::Text(text) | CellValue::Error(text) => text.clone(),
            CellValue::Float(value) => float_str(*value),
            CellValue::Int(value) => value.to_string(),
            CellValue::Bool(true) => "True".to_string(),
            CellValue::Bool(false) => "False".to_string(),
        }
    }

    fn text_len(&self) -> usize {
        match self {
            CellValue::Text(text) => text.len(),
            _ => 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LoadedCell {
    /// tmp_cell.row, 1-based. Up to 2^32, so wider than u32.
    pub row: u64,
    pub column: String,
    pub value: CellValue,
    /// `=...`
    pub formula: Option<String>,
}

/// One `Relationship` element's attributes: `attrib.get('Id')` and so on, by the plain attribute name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rel {
    pub id: Option<String>,
    pub target: Option<String>,
    pub rel_type: Option<String>,
}

/// What pyxlsb2 reads of `ElementTree.fromstring(part)`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelsXml {
    /// `len(root) > 0`, which is Python's truth value of the root element.
    pub has_children: bool,
    /// `root.findall('.//r:Relationship', nsmap)` for the namespace
    /// `http://schemas.openxmlformats.org/package/2006/relationships`: every descendant with that exact
    /// tag, in document order, not the root itself.
    pub relationships: Vec<Rel>,
}

/// What XlsbPackage is built on.
pub trait Package {
    /// `ZipFile.read(name)`. `Ok(None)` for the KeyError that get_file turns into None; any other
    /// exception as an XlError. An empty part is `Some(vec![])`: a BytesIO is always true.
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, XlError>;

    /// `get_xml_file(name)`. `Ok(None)` if `name` isn't exactly in `namelist()`. Otherwise read it
    /// (exceptions as for `read`), `.decode('utf_8')` strictly (UnicodeDecodeError) and
    /// `ElementTree.fromstring` the str (ParseError). The name has no fnmatch wildcards, so an exact
    /// match is the same as get_files' filter. The fall back between the two spellings is done here.
    fn rels_xml(&self, name: &str) -> Result<Option<RelsXml>, XlError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SheetInfo {
    /// None when the sheet record was too short. Then get_defined_names is unaffected, but any
    /// get_sheet_by_name reaching it raises AttributeError.
    pub name: Option<String>,
    /// 'macrosheet', 'worksheet', 'unknown', or None when no relationship has the sheet's rId.
    pub sheet_type: Option<String>,
    loc: Option<String>,
}

struct Externals {
    /// None until an EXTERN_SHEET record: Python's `[]`.
    sheets: Option<ExternSheets>,
    /// `len(SupportingLinks)`. Their brt is always in _SUP_LINK_TYPES, so only the count matters.
    links: usize,
}

pub struct Workbook {
    sheets: Vec<SheetInfo>,
    /// `defined_names`: name to `rec.formula`, both None-able, in dict order.
    names: IndexMap<Option<String>, Option<String>>,
    /// `list_names`, as positions in `names`.
    list_names: Vec<usize>,
    externals: Option<Externals>,
    /// `stringtable._strings`, or None without a sharedStrings part.
    strings: Option<Vec<Option<String>>>,
}

fn get_part(pkg: &dyn Package, name: &str, alt: &str) -> Result<Option<Vec<u8>>, XlError> {
    match pkg.read(name)? {
        Some(data) => Ok(Some(data)),
        None => pkg.read(alt),
    }
}

/// XlsbPackage.get_workbook_rels: `if not ret` also falls through for a root without children.
fn get_workbook_rels(pkg: &dyn Package) -> Result<Option<RelsXml>, XlError> {
    let rels = pkg.rels_xml("xl/_rels/workbook.bin.rels")?;
    if rels.as_ref().is_some_and(|rels| rels.has_children) {
        return Ok(rels);
    }
    pkg.rels_xml("xl\\_rels\\workbook.bin.rels")
}

/// Workbook.get_sheet_info: (type, loc).
fn sheet_info(
    rels: Option<&RelsXml>,
    r_id: Option<&str>,
    expired: &dyn Fn() -> bool,
) -> Result<(Option<String>, Option<String>), XlError> {
    let Some(rels) = rels else {
        return Err(none_attr("findall"));
    };
    let missing = |key: &str| XlError::new("KeyError", format!("'{key}'"));
    for (position, rel) in rels.relationships.iter().enumerate() {
        if position & 0xFFF == 0xFFF && expired() {
            return Err(XlError::pass_timeout());
        }
        let Some(id) = &rel.id else {
            return Err(missing("Id"));
        };
        if r_id == Some(id.as_str()) {
            let Some(target) = &rel.target else {
                return Err(missing("Target"));
            };
            let Some(rel_type) = &rel.rel_type else {
                return Err(missing("Type"));
            };
            let sheet_type = match rel_type.as_str() {
                MACROSHEET_TYPE | INTL_MACROSHEET_TYPE => "macrosheet",
                WORKSHEET_TYPE => "worksheet",
                _ => "unknown",
            };
            return Ok((Some(sheet_type.to_string()), Some(target.clone())));
        }
    }
    Ok((None, None))
}

impl Workbook {
    /// `pyxlsb2.open_workbook`.
    pub fn open(
        pkg: &dyn Package,
        log: &mut String,
        expired: &dyn Fn() -> bool,
    ) -> Result<Workbook, XlError> {
        Workbook::open_with_frames(pkg, DEFAULT_CALLER_FRAMES, log, expired)
    }

    /// `open`, for a caller with `caller_frames` Python frames on the stack at `XLSBWrapper(...)`,
    /// counting its own. It only moves where a formula about 990 levels deep hits RecursionError.
    pub fn open_with_frames(
        pkg: &dyn Package,
        caller_frames: usize,
        log: &mut String,
        expired: &dyn Fn() -> bool,
    ) -> Result<Workbook, XlError> {
        let rels = get_workbook_rels(pkg)?;
        let Some(data) = get_part(pkg, "xl/workbook.bin", "xl\\workbook.bin")? else {
            return Err(type_error(
                "'NoneType' object does not support the context manager protocol (missed __exit__ method)",
            ));
        };
        let mut book = Workbook {
            sheets: Vec::new(),
            names: IndexMap::new(),
            list_names: Vec::new(),
            externals: None,
            strings: None,
        };
        let frames_above = caller_frames.saturating_add(OPEN_FRAMES);
        let mut name_text = 0usize;
        let mut reader = RecordReader::new(&data);
        while let Some((rectype, rec)) = reader.next_record(expired)? {
            match (rectype, rec) {
                (reader::BUNDLE_SH, Rec::Sheet { r_id, name }) => {
                    if book.sheets.len() >= MAX_SHEETS {
                        return Err(memory_error());
                    }
                    let (sheet_type, loc) = sheet_info(rels.as_ref(), r_id.as_deref(), expired)?;
                    book.sheets.push(SheetInfo {
                        name,
                        sheet_type,
                        loc,
                    });
                }
                (reader::BEGIN_EXTERNALS, _) => {
                    book.externals = Some(Externals {
                        sheets: None,
                        links: 0,
                    });
                }
                (reader::EXTERN_SHEET, Rec::ExternSheet(sheets)) => {
                    let Some(externals) = &mut book.externals else {
                        return Err(type_error(
                            "'NoneType' object does not support item assignment",
                        ));
                    };
                    externals.sheets = Some(sheets);
                }
                (
                    reader::SUP_SELF | reader::SUP_SAME | reader::SUP_ADDIN | reader::SUP_BOOK_SRC,
                    _,
                ) => {
                    let Some(externals) = &mut book.externals else {
                        return Err(type_error(NOT_SUBSCRIPTABLE));
                    };
                    externals.links = externals.links.saturating_add(1);
                }
                (reader::NAME, Rec::Name { name, raw }) => {
                    if book.list_names.len() >= MAX_NAMES {
                        return Err(memory_error());
                    }
                    let (position, old) = book.names.insert_full(name, None);
                    book.list_names.push(position);
                    if let Some(Some(old)) = old {
                        name_text = name_text.saturating_sub(old.len());
                    }
                    let tokens = ptg::parse(raw, expired)?;
                    let mut ctx = Ctx {
                        book: &book,
                        log: &mut *log,
                        expired,
                        frames_above,
                    };
                    let formula = ptg::stringify(tokens, &mut ctx)?;
                    name_text = name_text.saturating_add(formula.as_ref().map_or(0, String::len));
                    if name_text > MAX_TOTAL_TEXT {
                        return Err(memory_error());
                    }
                    if let Some((_, slot)) = book.names.get_index_mut(position) {
                        *slot = formula;
                    }
                }
                _ => {}
            }
        }
        if let Some(data) = get_part(pkg, "xl/sharedStrings.bin", "xl\\sharedStrings.bin")? {
            book.strings = Some(read_strings(&data, expired)?);
        }
        if let Some(data) = get_part(pkg, "xl/styles.bin", "xl\\styles.bin")? {
            reader::check_styles(&data, expired)?;
        }
        Ok(book)
    }

    /// XLSBWrapper.get_defined_names: lower-cased key to (lower-cased key, `val.formula`), in dict
    /// order. The formula is a str or None; a key that is None raises AttributeError as `.lower()` does.
    pub fn defined_names(&self) -> Result<IndexMap<String, (String, Option<String>)>, XlError> {
        let mut names = IndexMap::with_capacity(self.names.len());
        for (key, formula) in &self.names {
            let Some(key) = key else {
                return Err(none_attr("lower"));
            };
            let lower = py_lower(key);
            names.insert(lower.clone(), (lower, formula.clone()));
        }
        Ok(names)
    }

    pub fn sheets(&self) -> &[SheetInfo] {
        &self.sheets
    }

    /// XLSBWrapper.load_cells for one sheet name, in the dict order of `boundsheet.cells`. Prints go to
    /// `log`. The name is optional because a sheet's name can be None.
    pub fn load_cells(
        &self,
        pkg: &dyn Package,
        sheet_name: Option<&str>,
        log: &mut String,
        expired: &dyn Fn() -> bool,
    ) -> Result<Vec<LoadedCell>, XlError> {
        self.load_cells_with_frames(pkg, sheet_name, DEFAULT_CALLER_FRAMES, log, expired)
    }

    /// `load_cells`, for a caller with `caller_frames` Python frames at `load_cells(...)`.
    pub fn load_cells_with_frames(
        &self,
        pkg: &dyn Package,
        sheet_name: Option<&str>,
        caller_frames: usize,
        log: &mut String,
        expired: &dyn Fn() -> bool,
    ) -> Result<Vec<LoadedCell>, XlError> {
        let data = self.sheet_part(pkg, sheet_name)?;
        let frames_above = caller_frames.saturating_add(LOAD_FRAMES);
        let mut reader = RecordReader::new(&data);
        // Worksheet._parse: without this record, rows() starts over from offset 0.
        let mut data_offset = 0;
        while let Some((rectype, _)) = reader.next_record(expired)? {
            if rectype == reader::BEGIN_SHEET_DATA {
                data_offset = reader.tell();
                break;
            }
        }
        reader.seek(data_offset);
        let mut loader = Loader {
            book: self,
            log,
            expired,
            frames_above,
            row_count: 0,
            kept: IndexMap::new(),
            text: 0,
        };
        // Worksheet.rows: a row is only processed when the next row or END_SHEET_DATA comes, so the
        // last row of a sheet without END_SHEET_DATA is dropped.
        let mut row: Option<Row<'_>> = None;
        let mut row_num = Some(-1i64);
        while let Some((rectype, rec)) = reader.next_record(expired)? {
            match (rectype, rec) {
                (reader::ROW_HDR, Rec::Row(num)) => {
                    let num_key = num.map(i64::from);
                    if num_key != row_num {
                        if let Some(done) = row.take()
                            && !loader.process_row(done)?
                        {
                            return Ok(loader.finish());
                        }
                        row_num = num_key;
                        row = Some(Row::new(num));
                    }
                }
                (reader::CELL_ISST, Rec::Cell(cell)) => {
                    if let (CellValue::Int(index), Some(col)) = (&cell.value, cell.col) {
                        let Some(strings) = &self.strings else {
                            return Err(none_attr("_strings"));
                        };
                        let value = match usize::try_from(*index) {
                            Ok(position) if position < strings.len() => RowValue::Shared(position),
                            _ => RowValue::Plain(CellValue::Int(*index)),
                        };
                        add_cell(&mut row, col, value, cell.formula, cell.style)?;
                    }
                }
                (reader::CELL_BLANK..=reader::FMLA_ERROR, Rec::Cell(cell)) => {
                    if let (false, Some(col)) = (cell.value == CellValue::None, cell.col) {
                        let value = RowValue::Plain(cell.value);
                        add_cell(&mut row, col, value, cell.formula, cell.style)?;
                    }
                }
                (reader::END_SHEET_DATA, _) => {
                    if let Some(done) = row.take() {
                        loader.process_row(done)?;
                    }
                    break;
                }
                _ => {}
            }
        }
        Ok(loader.finish())
    }

    /// Workbook.get_sheet_by_name and the check Worksheet._parse makes of its file.
    fn sheet_part(&self, pkg: &dyn Package, name: Option<&str>) -> Result<Vec<u8>, XlError> {
        let Some(name) = name else {
            return Err(none_attr("lower"));
        };
        let wanted = py_lower(name);
        let mut loc = None;
        for sheet in &self.sheets {
            let Some(sheet_name) = &sheet.name else {
                return Err(none_attr("lower"));
            };
            if py_lower(sheet_name) == wanted {
                loc = sheet.loc.as_ref();
                break;
            }
        }
        let Some(loc) = loc else {
            return Err(none_attr("rfind"));
        };
        let forward = format!("xl/{loc}");
        let back = format!("xl\\{}", loc.replace('/', "\\"));
        match get_part(pkg, &forward, &back)? {
            Some(data) => Ok(data),
            None => Err(none_attr("seek")),
        }
    }

    /// NamePtg.stringify.
    fn name_value(&self, idx: Option<u16>) -> Result<Option<String>, XlError> {
        let Some(idx) = idx else {
            return Err(type_error(
                "unsupported operand type(s) for -: 'NoneType' and 'int'",
            ));
        };
        // list_names[idx - 1], where idx 0 is the last.
        let position = match idx.checked_sub(1) {
            Some(position) => self.list_names.get(usize::from(position)),
            None => self.list_names.last(),
        };
        let found = position.and_then(|position| self.names.get_index(*position));
        let Some((name, formula)) = found else {
            return Err(index_error(LIST_RANGE));
        };
        Ok(match formula {
            Some(formula) if !formula.is_empty() && formula != "#NAME?" => Some(formula.clone()),
            _ => name.clone(),
        })
    }

    /// Workbook.resolve_extern_sheet_id, giving (first_sheet_idx, last_sheet_idx).
    fn resolve_extern(&self, extern_idx: u16) -> Result<(Option<i32>, Option<i32>), XlError> {
        let Some(externals) = &self.externals else {
            return Err(type_error(NOT_SUBSCRIPTABLE));
        };
        let Some(sheets) = &externals.sheets else {
            return Err(XlError::new(
                "AttributeError",
                "'list' object has no attribute 'external_sheets'",
            ));
        };
        let Some((link, first, last)) = sheets.get(extern_idx) else {
            return Err(index_error(LIST_RANGE));
        };
        let Some(link) = link else {
            return Err(type_error(
                "list indices must be integers or slices, not NoneType",
            ));
        };
        let links = i64::try_from(externals.links).unwrap_or(i64::MAX);
        let link = i64::from(link);
        if link >= links || link < -links {
            return Err(index_error(LIST_RANGE));
        }
        Ok((first, last))
    }
}

/// StringTable._parse.
fn read_strings(data: &[u8], expired: &dyn Fn() -> bool) -> Result<Vec<Option<String>>, XlError> {
    let mut strings = Vec::new();
    let mut reader = RecordReader::new(data);
    while let Some((rectype, rec)) = reader.next_record(expired)? {
        match (rectype, rec) {
            (reader::SST_ITEM, Rec::SstItem(text)) => {
                if strings.len() >= MAX_SHARED_STRINGS {
                    return Err(memory_error());
                }
                strings.push(text);
            }
            (reader::END_SST, _) => break,
            _ => {}
        }
    }
    Ok(strings)
}

enum RowValue {
    Plain(CellValue),
    /// A position in the shared strings, copied only if the cell is kept.
    Shared(usize),
}

struct RowCell<'a> {
    value: RowValue,
    formula: Option<&'a [u8]>,
    style: Option<u32>,
}

/// pyxlsb2's Row. Cells past the column cap are never visited, so they only count as "has a cell".
struct Row<'a> {
    num: Option<u32>,
    has_cells: bool,
    cells: std::collections::BTreeMap<u32, RowCell<'a>>,
}

impl Row<'_> {
    fn new(num: Option<u32>) -> Self {
        Row {
            num,
            has_cells: false,
            cells: std::collections::BTreeMap::new(),
        }
    }
}

fn add_cell<'a>(
    row: &mut Option<Row<'a>>,
    col: u32,
    value: RowValue,
    formula: Option<&'a [u8]>,
    style: Option<u32>,
) -> Result<(), XlError> {
    let Some(row) = row else {
        return Err(none_attr("_add_cell"));
    };
    row.has_cells = true;
    if col <= COLUMN_CAP {
        row.cells.insert(
            col,
            RowCell {
                value,
                formula,
                style,
            },
        );
    }
    Ok(())
}

/// The body of XLSBWrapper.load_cells' loops.
struct Loader<'a> {
    book: &'a Workbook,
    log: &'a mut String,
    expired: &'a dyn Fn() -> bool,
    frames_above: usize,
    row_count: u64,
    /// `boundsheet.cells`: a later cell with the same address keeps the first one's position.
    kept: IndexMap<(u32, u64), LoadedCell>,
    text: usize,
}

impl Loader<'_> {
    fn finish(self) -> Vec<LoadedCell> {
        self.kept.into_values().collect()
    }

    /// One pass of `for row in sheet`. False is the loop's `break` at the row cap.
    fn process_row(&mut self, row: Row<'_>) -> Result<bool, XlError> {
        if self.row_count > ROW_CAP {
            return Ok(false);
        }
        self.row_count += 1;
        if !row.has_cells {
            return Ok(true);
        }
        let Some(num) = row.num else {
            return Err(type_error(
                "unsupported operand type(s) for +: 'NoneType' and 'int'",
            ));
        };
        let row_number = u64::from(num) + 1;
        for (col, cell) in row.cells {
            self.process_cell(row_number, col, cell)?;
        }
        Ok(true)
    }

    fn process_cell(&mut self, row: u64, col: u32, cell: RowCell<'_>) -> Result<(), XlError> {
        if (self.expired)() {
            return Err(XlError::pass_timeout());
        }
        let shared = |position: usize| {
            let strings = self.book.strings.as_ref()?;
            strings.get(position)?.as_ref()
        };
        let tokens = ptg::parse(cell.formula.unwrap_or(&[]), self.expired)?;
        let mut formula = None;
        if !tokens.is_empty() {
            let mut ctx = Ctx {
                book: self.book,
                log: &mut *self.log,
                expired: self.expired,
                frames_above: self.frames_above,
            };
            let result = ptg::stringify(tokens, &mut ctx);
            match result {
                Ok(Some(text)) => formula = Some(format!("={text}")),
                Err(error) if error.kind == "PassTimeout" => return Err(error),
                // '=' + None raises too; both reach `print('ERROR ' + str(cell))`.
                Ok(None) | Err(_) => {
                    let value = match &cell.value {
                        RowValue::Plain(value) => value.py_str(),
                        RowValue::Shared(position) => fmt_opt(&shared(*position)),
                    };
                    // The Row is printed by object.__repr__; its address can't be reproduced.
                    self.log.push_str(&format!(
                        "ERROR Cell(row=<pyxlsb2.row.Row object at 0x0>, col={col}, value={value}, formula={}, style_id={})\n",
                        cell.formula.map_or_else(|| "None".to_string(), bytes_repr),
                        fmt_opt(&cell.style),
                    ));
                }
            }
        }
        let value = match cell.value {
            RowValue::Plain(value) => value,
            RowValue::Shared(position) => match shared(position) {
                Some(text) => {
                    if text.len() > MAX_TEXT {
                        return Err(memory_error());
                    }
                    CellValue::Text(text.clone())
                }
                None => CellValue::None,
            },
        };
        if value == CellValue::None && formula.is_none() {
            return Ok(());
        }
        let added = value.text_len() + formula.as_ref().map_or(0, String::len);
        self.text = self.text.saturating_add(added);
        if self.text > MAX_TOTAL_TEXT {
            return Err(memory_error());
        }
        if self.kept.len() >= MAX_CELLS && !self.kept.contains_key(&(col, row)) {
            return Err(memory_error());
        }
        let column = pyfmt::column_name(col);
        let new = LoadedCell {
            row,
            column,
            value,
            formula,
        };
        if let Some(old) = self.kept.insert((col, row), new) {
            let freed = old.value.text_len() + old.formula.as_ref().map_or(0, String::len);
            self.text = self.text.saturating_sub(freed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
