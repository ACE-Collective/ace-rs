//! XLMMacroDeobfuscator's `boundsheet.py`: cells, sheets and how a cell's address is read.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::OnceLock;

use indexmap::IndexMap;
use regex::Regex;

use super::value::{R, Value, attr_error, raise};

pub type CellRef = Rc<RefCell<Cell>>;
pub type Cells = Rc<RefCell<IndexMap<String, CellRef>>>;
pub type SheetRef = Rc<Sheet>;

pub struct Cell {
    pub sheet: Option<SheetRef>,
    pub column: Option<String>,
    pub row: Option<String>,
    pub formula: Option<String>,
    pub value: Value,
    /// `attributes['s']`, the one a macro can ask about through GET.CELL.
    pub style: Option<String>,
}

impl Cell {
    pub fn new(sheet: &SheetRef) -> Cell {
        Cell {
            sheet: Some(sheet.clone()),
            column: Some(String::new()),
            row: Some("0".to_owned()),
            formula: None,
            value: Value::None,
            style: None,
        }
    }

    /// `get_local_address`.
    pub fn local_address(&self) -> R<String> {
        match &self.column {
            Some(column) => Ok(format!("{column}{}", self.row.as_deref().unwrap_or("None"))),
            None => raise(
                "TypeError",
                "unsupported operand type(s) for +: 'NoneType' and 'str'",
            ),
        }
    }

    pub fn sheet_name(&self) -> String {
        self.sheet
            .as_ref()
            .map_or(String::new(), |s| s.name.clone())
    }

    /// `str(cell)`.
    pub fn to_py_str(&self) -> String {
        format!(
            "'{}'!{}{}",
            self.sheet_name(),
            self.column.as_deref().unwrap_or("None"),
            self.row.as_deref().unwrap_or("None")
        )
    }
}

pub struct Sheet {
    pub name: String,
    pub kind: &'static str,
    /// Replaced when a branch of the emulation restores what it saved.
    pub cells: RefCell<Cells>,
    pub row_height: RefCell<IndexMap<String, String>>,
    pub default_height: RefCell<Option<String>>,
}

impl Sheet {
    pub fn new(name: &str, kind: &'static str) -> SheetRef {
        Rc::new(Sheet {
            name: name.to_owned(),
            kind,
            cells: RefCell::new(Rc::new(RefCell::new(IndexMap::new()))),
            row_height: RefCell::new(IndexMap::new()),
            default_height: RefCell::new(None),
        })
    }

    pub fn cell(&self, address: &str) -> Option<CellRef> {
        self.cells.borrow().borrow().get(address).cloned()
    }
}

/// The three parts of a cell's address, each of which may be None.
pub type Address = (Option<String>, Option<String>, Option<String>);

fn regexes() -> &'static [Regex; 4] {
    static REGEXES: OnceLock<[Regex; 4]> = OnceLock::new();
    REGEXES.get_or_init(|| {
        let sheet = r"(?:(?P<sheetname>[^\s]+?|'.+?')";
        let build = |text: String| Regex::new(&format!("^(?:{text})")).expect("a valid expression");
        [
            build(format!(r"{sheet}!)?R(?P<row>\d+)C(?P<column>\d+)")),
            build(format!(r"{sheet}!)?\$?(?P<column>[a-zA-Z]+)\$?(?P<row>\d+)")),
            build(format!(
                r"{sheet}!)?R(\[?(?P<row>-?\d+)\]?)?C(\[?(?P<column>-?\d+)\]?)?"
            )),
            build(format!(
                r"{sheet}[!|$])?\$?(?P<column1>[a-zA-Z]+)\$?(?P<row1>\d+)\:?\$?(?P<column2>[a-zA-Z]+)\$?(?P<row2>\d+)"
            )),
        ]
    })
}

fn sheet_part(found: &regex::Captures<'_>) -> Option<String> {
    found
        .name("sheetname")
        .map(|m| m.as_str().trim_matches('\'').to_owned())
}

/// `Cell.parse_cell_addr`.
pub fn parse_cell_addr(address: &str) -> Address {
    let address = address.trim_matches('"');
    let [r1c1, a1, ..] = regexes();
    if let Some(found) = r1c1.captures(address) {
        let column = found["column"].parse::<i128>().unwrap_or(i128::MAX);
        return (
            sheet_part(&found),
            Some(column_name(column)),
            Some(found["row"].to_owned()),
        );
    }
    if let Some(found) = a1.captures(address) {
        return (
            sheet_part(&found),
            Some(found["column"].to_owned()),
            Some(found["row"].to_owned()),
        );
    }
    (None, None, None)
}

/// `Cell.parse_cell_addr(x)` of something that may not be a str.
pub fn parse_cell_addr_value(value: &Value) -> R<Address> {
    match value.as_text() {
        Some(text) => Ok(parse_cell_addr(&text)),
        None => attr_error(value.type_name(), "strip"),
    }
}

/// `Cell.parse_range_addr`'s five parts, or the three Nones that make a caller's unpacking fail.
pub fn parse_range_addr(address: &str) -> Option<(Option<String>, String, String, String, String)> {
    let found = regexes()[3].captures(address)?;
    Some((
        sheet_part(&found),
        found["column1"].to_owned(),
        found["row1"].to_owned(),
        found["column2"].to_owned(),
        found["row2"].to_owned(),
    ))
}

/// `Cell.convert_to_column_index`, to the width Python would need only for text no sheet has.
pub fn column_index(name: &str) -> i128 {
    let mut number: i128 = 0;
    let mut power: i128 = 1;
    for c in name.chars().rev() {
        let upper = c.to_uppercase().next().unwrap_or(c);
        let digit = (i128::from(u32::from(upper)) - 65 + 1).saturating_mul(power);
        number = number.saturating_add(digit);
        power = power.saturating_mul(26);
    }
    number
}

/// `Cell.convert_to_column_name`.
pub fn column_name(mut n: i128) -> String {
    let mut out = Vec::new();
    while n > 0 {
        let remainder = (n - 1).rem_euclid(26);
        n = (n - 1).div_euclid(26);
        out.push(char::from(65 + remainder as u8));
    }
    out.iter().rev().collect()
}

/// `Cell.get_abs_addr`.
pub fn abs_addr(base: &str, offset: &str) -> R<String> {
    let (_, base_col, base_row) = parse_cell_addr(base);
    let mut column_offset = 0;
    let mut row_offset = 0;
    if let Some(found) = regexes()[2].captures(offset) {
        let parse = |name: &str| -> R<i128> {
            match found.name(name) {
                Some(m) => Ok(m.as_str().parse().unwrap_or(0)),
                None => raise(
                    "TypeError",
                    "int() argument must be a string, a bytes-like object or a real number, not 'NoneType'",
                ),
            }
        };
        column_offset = parse("column")?;
        row_offset = parse("row")?;
    }
    let Some(base_col) = base_col else {
        return raise("TypeError", "'NoneType' object is not reversible");
    };
    let base_row: i128 = base_row.as_deref().unwrap_or("0").parse().unwrap_or(0);
    Ok(format!(
        "{}{}",
        column_name(column_index(&base_col) + column_offset),
        base_row + row_offset
    ))
}
