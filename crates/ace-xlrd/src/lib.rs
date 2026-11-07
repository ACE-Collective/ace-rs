//! What XLMMacroDeobfuscator reads of a legacy BIFF workbook: the parts of xlrd2 that
//! `xls_wrapper_2.py` calls, and that wrapper's data access.

mod book;
mod compdoc;
mod dbcs;
mod formula;
mod py;
mod pyval;
mod sheet;
mod tables;

use std::fmt;
use std::sync::Arc;

use indexmap::IndexMap;

pub use py::float_repr;
pub use pyval::{ArrItem, Ref3D};

use crate::formula::{O_ARR, O_NUM, O_REF, O_STRG, Operand};
use crate::py::{R, complex_repr, err, list_index_error, memory_error, repr_str, xlrd_err};
use crate::pyval::PyVal;

/// A Python exception as data: type name and `str(exc)`.
#[derive(Clone, Debug, PartialEq)]
pub struct XlError {
    pub kind: String,
    pub message: String,
}

impl fmt::Display for XlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for XlError {}

/// `xls_cell.value`, or GET.CELL's `data`.
#[derive(Clone, Debug, PartialEq)]
pub enum CellValue {
    /// GET.CELL's `data` when not implemented. A loaded cell's value is never None.
    None,
    /// str; a blank or padded cell is `""`. Shared: many cells can name one SST string.
    Text(Arc<str>),
    /// float: numbers, dates, RK values, row and font heights.
    Float(f64),
    /// int: a boolean (0, 1) or an error code. xlrd2 has no bool values.
    Int(i64),
}

/// One cell as XLSWrapper2.load_cells builds it.
#[derive(Clone, Debug, PartialEq)]
pub struct LoadedCell {
    /// 1-based, `cell.row`.
    pub row: u32,
    /// `"A"`..
    pub column: String,
    /// `"=..."`.
    pub formula: Option<String>,
    pub value: CellValue,
}

/// A value of XLSWrapper2.get_defined_names's dict. oNUM's value can be more than a float
/// because the name evaluator computes with Python's dynamic values: `+"a"` is oNUM with a str.
#[derive(Clone, Debug, PartialEq)]
pub enum NameValue {
    /// str.
    Text(String),
    /// float.
    Num(f64),
    /// int: `IF` over a missing argument gives 0.
    Int(i64),
    /// oNUM with no constant value.
    None,
    /// complex: a negative number to a fractional power.
    Complex(f64, f64),
    /// list of Ref3D: unary plus of a reference.
    Refs(Vec<Ref3D>),
    /// oARR's list.
    Arr(Vec<ArrItem>),
}

impl NameValue {
    /// `str(value)`.
    pub fn py_str(&self) -> String {
        match self {
            NameValue::Text(s) => s.clone(),
            NameValue::Num(f) => float_repr(*f),
            NameValue::Int(i) => i.to_string(),
            NameValue::None => "None".to_string(),
            NameValue::Complex(a, b) => complex_repr(*a, *b),
            NameValue::Refs(r) => PyVal::Refs(r.clone()).repr(),
            NameValue::Arr(a) => pyval::arr_repr(a),
        }
    }
}

/// `sheet.boundsheet_type`, from the sheet's BOF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SheetType {
    Macrosheet,
    Worksheet,
    Other,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SheetInfo {
    pub name: String,
    pub boundsheet_type: SheetType,
}

/// Where a hostile file would run Python out of memory, this raises MemoryError instead.
#[derive(Clone)]
pub(crate) struct Limits {
    max_cells: u64,
    cells: u64,
    max_rows: u64,
    rows: u64,
    max_slots: u64,
    slots: u64,
    pub(crate) max_stream: usize,
    pub(crate) max_strings: usize,
    pub(crate) max_text: usize,
    text: usize,
    empty: Arc<str>,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_cells: MAX_CELLS,
            cells: 0,
            max_rows: MAX_ROWS,
            rows: 0,
            max_slots: MAX_DENSE_SLOTS,
            slots: 0,
            max_stream: MAX_STREAM,
            max_strings: MAX_STRINGS,
            max_text: MAX_TEXT,
            text: 0,
            empty: Arc::from(""),
        }
    }
}

impl Limits {
    pub(crate) fn empty_text(&self) -> Arc<str> {
        self.empty.clone()
    }

    pub(crate) fn spend_cell(&mut self) -> R<()> {
        self.cells += 1;
        if self.cells > self.max_cells {
            return Err(memory_error());
        }
        Ok(())
    }

    pub(crate) fn spend_rows(&mut self, n: i64) -> R<()> {
        self.rows = self.rows.saturating_add(n.max(0) as u64);
        if self.rows > self.max_rows {
            return Err(memory_error());
        }
        Ok(())
    }

    pub(crate) fn spend_slots(&mut self, n: i64) -> R<()> {
        self.slots = self.slots.saturating_add(n.max(0) as u64);
        if self.slots > self.max_slots {
            return Err(memory_error());
        }
        Ok(())
    }

    pub(crate) fn spend_text(&mut self, n: usize) -> R<()> {
        self.text = self.text.saturating_add(n);
        if self.text > self.max_text {
            return Err(memory_error());
        }
        Ok(())
    }
}

/// Used cells over all sheets.
pub const MAX_CELLS: u64 = 8_000_000;
/// Rows xlrd2 would have appended, over all sheets. Sheet rows are capped at 65536 each, but a
/// repeated DIMENSION record resets the count, so a small file can ask for any number.
pub const MAX_ROWS: u64 = 8_000_000;
/// Slots of xlrd2's dense matrix, about 19 bytes each in Python. A real sheet tops out at 2**24;
/// only a MERGEDCELLS range past column 256 goes beyond it.
pub const MAX_DENSE_SLOTS: u64 = 1 << 30;
/// Input file size.
pub const MAX_STREAM: usize = 1 << 31;
/// Shared strings in one SST.
pub const MAX_STRINGS: usize = 16_000_000;
/// Bytes of text in cells, formulas and one SST.
pub const MAX_TEXT: usize = 1 << 31;

pub(crate) struct NameResult {
    pub(crate) result: Option<Operand>,
}

/// xlrd2's Book, after open_workbook.
pub struct Book {
    sheet_list: Vec<Option<sheet::Sheet>>,
    sheet_names: Vec<String>,
    names: Vec<NameResult>,
    name_map: IndexMap<String, Vec<usize>>,
    xf_list: Vec<book::Xf>,
    font_list: Vec<book::Font>,
    normal_style: Option<i64>,
    nsheets: usize,
}

impl Book {
    /// `xlrd2.open_workbook(.., formatting_info=True)`. What it prints goes to `log`, in order.
    /// `expired` is polled in any loop a hostile file can inflate; when true this returns
    /// `XlError { kind: "PassTimeout", .. }`.
    pub fn open(
        data: &[u8],
        log: &mut String,
        expired: &dyn Fn() -> bool,
    ) -> Result<Book, XlError> {
        if data.starts_with(b"PK\x03\x04") {
            return Err(book::zip_refusal(data));
        }
        let l = book::open_xls(data, log, expired, Limits::default())?;
        Ok(Book {
            sheet_list: l.sheet_list,
            sheet_names: l.sheet_names,
            names: l.names,
            name_map: l.name_map,
            xf_list: l.xf_list,
            font_list: l.font_list,
            normal_style: l.normal_style,
            nsheets: l.nsheets,
        })
    }

    /// XLSWrapper2.get_defined_names's dict, in insertion order with lower-cased keys. It can
    /// raise as the Python does, from the mangled auto_open case or an int left on a name's
    /// stack.
    pub fn defined_names(&self) -> Result<IndexMap<String, NameValue>, XlError> {
        let mut out: IndexMap<String, NameValue> = IndexMap::new();
        for (name_obj, cells) in &self.name_map {
            let mut name = name_obj.to_lowercase();
            let index = if cells.len() > 1 { 1 } else { 0 };
            let first = cells
                .first()
                .and_then(|i| self.names.get(*i))
                .ok_or_else(list_index_error)?;
            let result = first.result.as_ref();
            let mut filtered = name.to_lowercase();
            if name != filtered {
                if out.contains_key(&filtered) {
                    filtered.push_str(&index.to_string());
                }
                if let Some(r) = result {
                    let text = r.attr("text")?.text.clone();
                    out.insert(filtered, NameValue::Text(text));
                }
            }
            if out.contains_key(&name) {
                name.push_str(&index.to_string());
            }
            let Some(r) = result else {
                continue;
            };
            let text = &r.attr("text")?.text;
            match r.kind {
                O_NUM => {
                    out.insert(name, value_of(r.value.as_ref()));
                }
                O_STRG => {
                    out.insert(name, NameValue::Text(text.clone()));
                }
                O_ARR => {
                    out.insert(name, value_of(r.value.as_ref()));
                }
                O_REF => {
                    if text.contains('$') {
                        out.insert(name, NameValue::Text(text.clone()));
                    } else if name.contains("auto_open") {
                        let refs = match r.value.as_ref() {
                            Some(PyVal::Refs(v)) => v,
                            _ => {
                                return Err(err(
                                    "TypeError",
                                    "'NoneType' object is not subscriptable",
                                ));
                            }
                        };
                        let coords = refs.first().ok_or_else(list_index_error)?.coords;
                        let sheet = text.split('!').next().unwrap_or("").replace('\'', "");
                        out.insert(
                            name,
                            NameValue::Text(format!(
                                "{sheet}!${}${}",
                                column_name(coords[5]),
                                coords[3]
                            )),
                        );
                    }
                }
                _ => {}
            }
        }
        Ok(out)
    }

    /// `book.sheets()`.
    pub fn sheets(&self) -> Vec<SheetInfo> {
        self.sheet_list
            .iter()
            .take(self.nsheets)
            .flatten()
            .map(|s| SheetInfo {
                name: s.name.clone(),
                boundsheet_type: match s.boundsheet_type {
                    book::XL_MACROSHEET => SheetType::Macrosheet,
                    book::XL_WORKSHEET => SheetType::Worksheet,
                    _ => SheetType::Other,
                },
            })
            .collect()
    }

    /// XLSWrapper2.load_cells for one sheet, in the iteration order of Python's set
    /// `sheet.used_cells`. Its `print('CELL(Formula): ...')` path needs get_used_cells to raise,
    /// and open has already raised for anything that could, so `_log` is never written.
    pub fn load_cells(&self, sheet_index: usize, _log: &mut String) -> Vec<LoadedCell> {
        let Some(Some(sheet)) = self.sheet_list.get(sheet_index) else {
            return Vec::new();
        };
        set_order(&sheet.insertion)
            .into_iter()
            .filter_map(|key| {
                let c = sheet.cells.get(&key)?;
                Some(LoadedCell {
                    row: key.0 + 1,
                    column: column_name(i64::from(key.1) + 1),
                    formula: c
                        .formula
                        .as_ref()
                        .filter(|f| !f.is_empty())
                        .map(|f| format!("={f}")),
                    value: c.value.clone(),
                })
            })
            .collect()
    }

    /// XLSWrapper2.get_cell_info: (data, not_exist, not_implemented). `info_type_id` is the
    /// wrapper's `int(float(x))`, already converted.
    pub fn get_cell_info(
        &self,
        sheet_name: &str,
        col: &str,
        row: &str,
        info_type_id: i64,
    ) -> Result<(CellValue, bool, bool), XlError> {
        let idx = self
            .sheet_names
            .iter()
            .position(|n| n == sheet_name)
            .ok_or_else(|| xlrd_err(format!("No sheet named <{}>", repr_str(sheet_name))))?;
        let sheet = self
            .sheet_list
            .get(idx)
            .ok_or_else(list_index_error)?
            .as_ref()
            .ok_or_else(list_index_error)?;
        let row = py_int(row)? - 1;
        let column = column_index(col)? - 1;

        if info_type_id == 5 {
            let (value, _xf) = sheet_cell(sheet, row, column)?;
            return Ok((value, false, false));
        }
        if info_type_id == 17 {
            let height = i64::try_from(row)
                .ok()
                .and_then(|r| sheet.rowinfo.get(&r))
                .map(|(h, _)| *h)
                .or(sheet.default_row_height)
                .ok_or_else(|| {
                    err(
                        "TypeError",
                        "int() argument must be a string, a bytes-like object or a real number, not 'NoneType'",
                    )
                })?;
            let point = height as f64 * 0.05;
            let data = (point * 4.0).round_ties_even() / 4.0;
            return Ok((CellValue::Float(data), false, false));
        }
        let used = u32::try_from(row)
            .is_ok_and(|r| u32::try_from(column).is_ok_and(|c| sheet.cells.contains_key(&(r, c))));
        let mut fmt_at: Option<i64> = None;
        if used {
            let (_v, xf) = sheet_cell(sheet, row, column)?;
            if xf < self.xf_list.len() as i64 {
                fmt_at = Some(xf);
            }
        }
        let xf_index = match fmt_at {
            Some(x) => x,
            None => self
                .normal_style
                .ok_or_else(|| err("KeyError", "'Normal'"))?,
        };
        let fmt = self
            .xf_list
            .get(xf_index as usize)
            .ok_or_else(list_index_error)?;
        let font = self
            .font_list
            .get(fmt.font_index as usize)
            .ok_or_else(list_index_error)?;
        let int = |v: i64| Ok((CellValue::Int(v), false, false));
        match info_type_id {
            8 => int(fmt.hor_align + 1),
            19 => Ok((CellValue::Float(font.height as f64 * 0.05), false, false)),
            24 => int(if font.colour_index > 7 {
                font.colour_index - 7
            } else {
                font.colour_index
            }),
            38 => int(if font.colour_index > 7 {
                fmt.pattern_colour_index - 7
            } else {
                font.colour_index
            }),
            50 => int(fmt.vert_align + 1),
            _ => Ok((CellValue::None, false, true)),
        }
    }
}

fn value_of(v: Option<&PyVal>) -> NameValue {
    match v {
        None => NameValue::None,
        Some(PyVal::Int(i)) => NameValue::Int(*i),
        Some(PyVal::Float(f)) => NameValue::Num(*f),
        Some(PyVal::Complex(a, b)) => NameValue::Complex(*a, *b),
        Some(PyVal::Str(s)) => NameValue::Text(s.clone()),
        Some(PyVal::Refs(r)) => NameValue::Refs(r.clone()),
        Some(PyVal::Arr(a)) => NameValue::Arr(a.clone()),
    }
}

/// `sheet.cell(rowx, colx)`: its value and xf_index, with Python's index rules.
fn sheet_cell(s: &sheet::Sheet, rowx: i128, colx: i128) -> R<(CellValue, i64)> {
    let huge = || err("IndexError", "cannot fit 'int' into an index-sized integer");
    if i64::try_from(rowx).is_err() {
        return Err(huge());
    }
    let r = py::py_index(rowx, s.row_lens.len()).ok_or_else(list_index_error)?;
    if i64::try_from(colx).is_err() {
        return Err(huge());
    }
    let len = s.row_lens.get(r).copied().unwrap_or(0) as usize;
    let c = py::py_index(colx, len).ok_or_else(|| err("IndexError", "array index out of range"))?;
    let cell = s.cells.get(&(r as u32, c as u32));
    let xf = cell.map_or(-1, |x| i64::from(x.xf_index));
    let xf = s.xf_fallback(xf, rowx, colx);
    let value = cell
        .map(|x| x.value.clone())
        .unwrap_or_else(|| CellValue::Text(Arc::from("")));
    Ok((value, xf))
}

/// boundsheet.Cell.convert_to_column_name.
fn column_name(n: i64) -> String {
    let mut n = n;
    let mut out = Vec::new();
    while n > 0 {
        let rem = (n - 1).rem_euclid(26);
        n = (n - 1).div_euclid(26);
        out.push(char::from(b'A' + rem as u8));
    }
    out.iter().rev().collect()
}

/// boundsheet.Cell.convert_to_column_index.
fn column_index(s: &str) -> R<i128> {
    let mut number = 0i128;
    let mut power = 1i128;
    for ch in s.chars().rev() {
        let mut up = ch.to_uppercase();
        let first = up.next().unwrap_or(ch);
        let extra = up.count();
        if extra > 0 {
            return Err(err(
                "TypeError",
                format!(
                    "ord() expected a character, but string of {} found",
                    extra + 1
                ),
            ));
        }
        let digit = (i128::from(first as u32) - 65 + 1).saturating_mul(power);
        number = number.saturating_add(digit);
        power = power.saturating_mul(26);
    }
    Ok(number)
}

/// `int(str)`, ASCII digits only; past i128 saturates, which indexes the same as any huge int.
fn py_int(t: &str) -> R<i128> {
    let bad = || {
        err(
            "ValueError",
            format!("invalid literal for int() with base 10: {}", repr_str(t)),
        )
    };
    let body = t.trim_matches(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c));
    let (neg, digits) = match body.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, body.strip_prefix('+').unwrap_or(body)),
    };
    let mut v = 0i128;
    let mut prev_digit = false;
    let mut any = false;
    for c in digits.chars() {
        if c == '_' {
            if !prev_digit {
                return Err(bad());
            }
            prev_digit = false;
            continue;
        }
        let d = c.to_digit(10).ok_or_else(bad)?;
        v = v.saturating_mul(10).saturating_add(i128::from(d));
        prev_digit = true;
        any = true;
    }
    if !any || !prev_digit {
        return Err(bad());
    }
    Ok(if neg { -v } else { v })
}

/// The iteration order of a CPython set of (rowx, colx) tuples added in this order: the table
/// and probing of Objects/setobject.c and tuple hashing of Objects/tupleobject.c.
fn set_order(keys: &[(u32, u32)]) -> Vec<(u32, u32)> {
    const LINEAR_PROBES: usize = 9;
    const PERTURB_SHIFT: u32 = 5;
    fn hash(k: (u32, u32)) -> u64 {
        const P1: u64 = 11400714785074694791;
        const P2: u64 = 14029467366897019727;
        const P5: u64 = 2870177450012600261;
        let mut acc = P5;
        for lane in [u64::from(k.0), u64::from(k.1)] {
            acc = acc.wrapping_add(lane.wrapping_mul(P2));
            acc = acc.rotate_left(31);
            acc = acc.wrapping_mul(P1);
        }
        acc = acc.wrapping_add(2u64 ^ (P5 ^ 3527539));
        if acc == u64::MAX { 1546275796 } else { acc }
    }
    fn insert_clean(table: &mut [Option<(u64, (u32, u32))>], h: u64, key: (u32, u32)) {
        let mask = table.len() - 1;
        let mut perturb = h;
        let mut i = (h as usize) & mask;
        loop {
            let limit = if i + LINEAR_PROBES <= mask {
                LINEAR_PROBES
            } else {
                0
            };
            for j in 0..=limit {
                if let Some(slot) = table.get_mut(i + j)
                    && slot.is_none()
                {
                    *slot = Some((h, key));
                    return;
                }
            }
            perturb >>= PERTURB_SHIFT;
            i = (i
                .wrapping_mul(5)
                .wrapping_add(1)
                .wrapping_add(perturb as usize))
                & mask;
        }
    }
    let mut table: Vec<Option<(u64, (u32, u32))>> = vec![None; 8];
    let mut used = 0usize;
    for &key in keys {
        let h = hash(key);
        let mask = table.len() - 1;
        let mut perturb = h;
        let mut i = (h as usize) & mask;
        'probe: loop {
            let limit = if i + LINEAR_PROBES <= mask {
                LINEAR_PROBES
            } else {
                0
            };
            for j in 0..=limit {
                if let Some(slot) = table.get_mut(i + j)
                    && slot.is_none()
                {
                    *slot = Some((h, key));
                    break 'probe;
                }
            }
            perturb >>= PERTURB_SHIFT;
            i = (i
                .wrapping_mul(5)
                .wrapping_add(1)
                .wrapping_add(perturb as usize))
                & mask;
        }
        used += 1;
        if used * 5 >= mask * 3 {
            let minused = if used > 50000 { used * 2 } else { used * 4 };
            let mut newsize = 8usize;
            while newsize <= minused {
                newsize <<= 1;
            }
            let mut new_table = vec![None; newsize];
            for (eh, ek) in table.iter().flatten() {
                insert_clean(&mut new_table, *eh, *ek);
            }
            table = new_table;
        }
    }
    table.into_iter().flatten().map(|(_, k)| k).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../samples/ace4/office/xlm_biff8.xls"
    );

    fn open_sample() -> Book {
        let data = std::fs::read(SAMPLE).expect("sample");
        let mut log = String::new();
        Book::open(&data, &mut log, &|| false).expect("opens")
    }

    #[test]
    fn reads_the_macro_sample() {
        let book = open_sample();
        let sheets = book.sheets();
        assert!(!sheets.is_empty());
        let mac = sheets
            .iter()
            .position(|s| s.boundsheet_type == SheetType::Macrosheet)
            .expect("macro sheet");
        let mut log = String::new();
        let cells = book.load_cells(mac, &mut log);
        assert!(cells.iter().any(|c| c.formula.is_some()));
        assert!(log.is_empty());
    }

    #[test]
    fn missing_sheet_raises_xlrd_error() {
        let book = open_sample();
        let e = book.get_cell_info("nope", "A", "1", 5).expect_err("raises");
        assert_eq!(e.kind, "XLRDError");
        assert_eq!(e.message, "No sheet named <'nope'>");
    }

    #[test]
    fn garbage_is_refused_like_python() {
        let mut log = String::new();
        let e = Book::open(b"not a workbook", &mut log, &|| false)
            .err()
            .expect("refused");
        assert_eq!(e.kind, "XLRDError");
        assert_eq!(
            e.message,
            "Unsupported format, or corrupt file: Expected BOF record; found b'not a wo'"
        );
    }

    #[test]
    fn expired_stops_with_pass_timeout() {
        let data = std::fs::read(SAMPLE).expect("sample");
        let mut log = String::new();
        let e = Book::open(&data, &mut log, &|| true)
            .err()
            .expect("expired");
        assert_eq!(e.kind, "PassTimeout");
    }

    #[test]
    fn float_repr_matches_python() {
        assert_eq!(float_repr(1.0), "1.0");
        assert_eq!(float_repr(1e16), "1e+16");
        assert_eq!(float_repr(1e-5), "1e-05");
        assert_eq!(float_repr(0.0001), "0.0001");
        assert_eq!(float_repr(-0.0), "-0.0");
        assert_eq!(float_repr(123456789012345680.0), "1.2345678901234568e+17");
    }

    #[test]
    fn name_values_render_like_python() {
        let a = NameValue::Arr(vec![ArrItem::Num(1.5), ArrItem::Text("it's".to_string())]);
        assert_eq!(a.py_str(), "[1.5, \"it's\"]");
        assert_eq!(NameValue::Complex(0.0, 2.0).py_str(), "2j");
        assert_eq!(NameValue::Complex(1.0, -2.0).py_str(), "(1-2j)");
    }

    #[test]
    fn set_order_matches_cpython() {
        // list(s) from CPython 3.14 after adding these in this order.
        let keys = [(0, 0), (0, 1), (1, 0), (5, 7), (100, 200)];
        assert_eq!(
            set_order(&keys),
            vec![(0, 1), (100, 200), (0, 0), (5, 7), (1, 0)]
        );
    }
}
