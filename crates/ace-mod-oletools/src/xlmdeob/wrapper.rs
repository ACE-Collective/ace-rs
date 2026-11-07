//! XLMMacroDeobfuscator's three workbook wrappers. `xlsm_wrapper.py` is here whole, on
//! `pyxml::sax_parse` for untangle; `ace-xlrd` and `ace-xlsb` read the other two formats.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Instant;

use indexmap::IndexMap;
use regex::Regex;

use super::sheet::{Cell, Sheet, SheetRef, parse_cell_addr};
use super::value::{R, Raised, Value, attr_error, index_error, raise};
use crate::py::{PyErr, repr_str};
use crate::pyxml::{self, Element};
use crate::pyzip::ZipFile;

pub type Names = Rc<RefCell<IndexMap<String, Value>>>;

/// Text for stdout, past whose limit a pass is treated as one that ran out of time.
pub struct Out {
    pub text: String,
}

pub const OUTPUT_LIMIT: usize = 256 * 1024 * 1024;

impl Out {
    pub fn print(&mut self, line: &str) -> R<()> {
        self.text.push_str(line);
        self.text.push('\n');
        if self.text.len() > OUTPUT_LIMIT {
            return Err(Raised::Limit);
        }
        Ok(())
    }
}

pub type OutRef = Rc<RefCell<Out>>;

pub fn from_py(error: PyErr) -> Raised {
    // only its message is printed, and nothing in the interpreter asks a reader's error for its kind
    Raised::Exception {
        kind: "Exception",
        message: error.message,
    }
}

fn from_xl(kind: String, message: String) -> Raised {
    if kind == "PassTimeout" {
        return Raised::Timeout;
    }
    from_py(PyErr { kind, message })
}

/// `get_cell_info`'s answer: data, not_exist, not_implemented.
pub type CellInfo = (Value, bool, bool);

/// `hasattr`/`getattr` on untangle's Element: one child is itself, more are a list.
enum Attr<'a> {
    None,
    One(&'a Element),
    Many(Vec<&'a Element>),
}

/// untangle's name for a tag: `-`, `.` and `:` become `_`, and a keyword takes a `_` after it. No name
/// the wrapper asks for is a keyword, and one in a file can't then match.
fn untangled(tag: &str) -> String {
    tag.replace(['-', '.', ':'], "_")
}

fn attr<'a>(element: &'a Element, name: &str) -> Attr<'a> {
    let found: Vec<&Element> = element
        .children
        .iter()
        .filter(|child| untangled(&child.tag) == name)
        .collect();
    match found.len() {
        0 => Attr::None,
        1 => Attr::One(found[0]),
        _ => Attr::Many(found),
    }
}

/// `element.name` where the code goes on to use it as one element.
fn one<'a>(element: &'a Element, name: &str) -> R<&'a Element> {
    match attr(element, name) {
        Attr::One(found) => Ok(found),
        Attr::Many(_) => attr_error("list", "?"),
        Attr::None => raise(
            "AttributeError",
            format!("'{}' has no attribute '{name}'", untangled(&element.tag)),
        ),
    }
}

/// `for x in element.name`.
fn each<'a>(element: &'a Element, name: &str) -> R<Vec<&'a Element>> {
    match attr(element, name) {
        Attr::One(found) => Ok(vec![found]),
        Attr::Many(found) => Ok(found),
        Attr::None => raise(
            "AttributeError",
            format!("'{}' has no attribute '{name}'", untangled(&element.tag)),
        ),
    }
}

fn has(element: &Element, name: &str) -> bool {
    !matches!(attr(element, name), Attr::None)
}

fn cdata(element: &Element) -> String {
    element.text.clone().unwrap_or_default()
}

/// `fnmatch.fnmatch(name, pattern)`.
fn fnmatch(name: &str, pattern: &str) -> bool {
    if !pattern.contains(['*', '?', '[']) {
        return name == pattern;
    }
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::from("(?s)^(?:");
    let mut at = 0;
    while at < chars.len() {
        let c = chars[at];
        at += 1;
        match c {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            '[' => {
                let mut j = at;
                if chars.get(j) == Some(&'!') {
                    j += 1;
                }
                if chars.get(j) == Some(&']') {
                    j += 1;
                }
                while j < chars.len() && chars[j] != ']' {
                    j += 1;
                }
                if j >= chars.len() {
                    out.push_str("\\[");
                } else {
                    let mut set: String = chars[at..j].iter().collect();
                    at = j + 1;
                    let negate = set.starts_with('!');
                    if negate {
                        set.remove(0);
                    }
                    let inner = set
                        .replace('\\', "\\\\")
                        .replace('[', "\\[")
                        .replace(']', "\\]");
                    if negate {
                        out.push_str(&format!("[^{inner}]"));
                    } else {
                        out.push_str(&format!("[{inner}]"));
                    }
                }
            }
            other => out.push_str(&regex::escape(&other.to_string())),
        }
    }
    out.push_str(")$");
    Regex::new(&out).is_ok_and(|regex| regex.is_match(name))
}

/// The `decode('utf_8')` of a part.
fn decode_utf8(data: &[u8]) -> R<String> {
    match std::str::from_utf8(data) {
        Ok(text) => Ok(text.to_owned()),
        Err(error) => {
            let at = error.valid_up_to();
            let byte = data.get(at).copied().unwrap_or(0);
            let (end, reason) = match error.error_len() {
                None => (data.len(), "unexpected end of data"),
                Some(1) if !(0xC2..=0xF4).contains(&byte) => (at + 1, "invalid start byte"),
                Some(length) => (at + length, "invalid continuation byte"),
            };
            let place = if end - at > 1 {
                format!("in position {at}-{}", end - 1)
            } else {
                format!("in position {at}")
            };
            raise(
                "UnicodeDecodeError",
                format!("'utf-8' codec can't decode byte 0x{byte:02x} {place}: {reason}"),
            )
        }
    }
}

/// A relationship's Target and Type, by its Id.
type Relationships = HashMap<Option<String>, (Option<String>, Option<String>)>;

struct SheetInfo {
    sheet: SheetRef,
    xml: Option<Rc<Element>>,
}

pub struct Xlsm {
    data: Vec<u8>,
    types: IndexMap<String, Option<String>>,
    workbook: Option<Rc<Element>>,
    workbook_rels: Option<Rc<Element>>,
    relationships: Option<Relationships>,
    style: Option<Rc<Element>>,
    shared_strings: Option<Option<Vec<String>>>,
    expired: Rc<dyn Fn() -> bool>,
}

impl Xlsm {
    fn new(data: Vec<u8>, expired: Rc<dyn Fn() -> bool>) -> R<Xlsm> {
        let mut xlsm = Xlsm {
            data,
            types: IndexMap::new(),
            workbook: None,
            workbook_rels: None,
            relationships: None,
            style: None,
            shared_strings: None,
            expired,
        };
        xlsm.types = xlsm.get_types()?;
        Ok(xlsm)
    }

    fn get_types(&self) -> R<IndexMap<String, Option<String>>> {
        let mut result = IndexMap::new();
        if let Some(main) = self.get_xml_file("[Content_Types].xml", false)? {
            // the document's root: hasattr(main, 'Types')
            if untangled(&main.tag) == "Types" {
                let key = |e: &Element| e.get("ContentType").map(str::to_owned);
                if has(&main, "Override") {
                    for item in each(&main, "Override")? {
                        if let Some(k) = key(item) {
                            result.insert(k, item.get("PartName").map(str::to_owned));
                        }
                    }
                }
                if has(&main, "Default") {
                    for item in each(&main, "Default")? {
                        if let Some(k) = key(item) {
                            result.insert(k, item.get("Extension").map(str::to_owned));
                        }
                    }
                }
            }
        }
        Ok(result)
    }

    /// `get_files([filter])`.
    fn get_files(&self, filter: &str) -> R<Vec<(String, Vec<u8>)>> {
        let zip = ZipFile::new(&self.data).map_err(from_py)?;
        let names: Vec<String> = zip.namelist().into_iter().map(str::to_owned).collect();
        let mut result: IndexMap<String, Vec<u8>> = IndexMap::new();
        for name in &names {
            if name == filter || fnmatch(name, filter) {
                result.insert(name.clone(), zip.read(name).map_err(from_py)?);
            }
        }
        if result.is_empty() {
            let backslashed = filter.replace('/', "\\");
            for name in &names {
                if *name == backslashed || fnmatch(name, &backslashed) {
                    result.insert(name.replace('\\', "/"), zip.read(name).map_err(from_py)?);
                }
            }
        }
        Ok(result.into_iter().collect())
    }

    fn get_xml_file(&self, name: &str, ignore_cells: bool) -> R<Option<Rc<Element>>> {
        if (self.expired)() {
            return Err(Raised::Timeout);
        }
        let name = name.strip_prefix('/').unwrap_or(name);
        let files = self.get_files(name)?;
        if files.len() != 1 {
            return Ok(None);
        }
        let Some((_, content)) = files.iter().find(|(key, _)| key == name) else {
            return raise("KeyError", repr_str(name));
        };
        let mut text = decode_utf8(content)?;
        if ignore_cells {
            static EMPTY: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
            let regex = EMPTY.get_or_init(|| Regex::new("<c[^>]+/>").expect("a valid expression"));
            if let std::borrow::Cow::Owned(replaced) = regex.replace_all(&text, "") {
                text = replaced;
            }
        }
        Ok(Some(Rc::new(pyxml::sax_parse(&text).map_err(from_py)?)))
    }

    fn get_workbook_path(&self) -> R<(String, String, String)> {
        let mut path = Some("xl/workbook.xml".to_owned());
        for kind in [
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
            "application/vnd.ms-excel.sheet.macroEnabled.main+xml",
        ] {
            if let Some(found) = self.types.get(kind) {
                path = found.clone();
                break;
            }
        }
        let Some(path) = path else {
            return attr_error("NoneType", "lstrip");
        };
        let path = path.trim_start_matches('/').to_owned();
        Ok(match path.split_once('/') {
            Some((dir, name)) => (path.clone(), dir.to_owned(), name.to_owned()),
            None => (path.clone(), String::new(), path.clone()),
        })
    }

    fn get_workbook(&mut self) -> R<Option<Rc<Element>>> {
        if self.workbook.is_none() {
            let (path, _, _) = self.get_workbook_path()?;
            self.workbook = self.get_xml_file(&path, false)?;
        }
        Ok(self.workbook.clone())
    }

    fn get_workbook_rels(&mut self) -> R<Option<Rc<Element>>> {
        if self.workbook_rels.is_none() {
            let mut kind = Some("rels".to_owned());
            if let Some(found) = self
                .types
                .get("application/vnd.openxmlformats-package.relationships+xml")
            {
                kind = found.clone();
            }
            let (_, dir, name) = self.get_workbook_path()?;
            let kind = kind.unwrap_or_else(|| "None".to_owned());
            let path = format!("{dir}/_{kind}/{name}.{kind}");
            self.workbook_rels = self.get_xml_file(&path, false)?;
        }
        Ok(self.workbook_rels.clone())
    }

    fn get_sheet_info(&mut self, r_id: Option<&str>) -> R<(Option<&'static str>, Option<String>)> {
        // get_sheet_info asks for the file even if the relationships are already held
        let rels = self.get_workbook_rels()?;
        if self.relationships.is_none() {
            let mut result = HashMap::new();
            if let Some(main) = &rels
                && untangled(&main.tag) == "Relationships"
                && has(main, "Relationship")
            {
                for item in each(main, "Relationship")? {
                    result.insert(
                        item.get("Id").map(str::to_owned),
                        (
                            item.get("Target").map(str::to_owned),
                            item.get("Type").map(str::to_owned),
                        ),
                    );
                }
            }
            self.relationships = Some(result);
        }
        let key = r_id.map(str::to_owned);
        let Some((target, kind)) = self.relationships.as_ref().and_then(|map| map.get(&key)) else {
            return Ok((None, None));
        };
        let sheet_type = match kind.as_deref() {
            Some(
                "http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet"
                | "http://schemas.microsoft.com/office/2006/relationships/xlIntlMacrosheet",
            ) => "Macrosheet",
            Some(
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet",
            ) => "Worksheet",
            _ => "Unknown",
        };
        Ok((Some(sheet_type), target.clone()))
    }

    fn defined_names(&mut self) -> R<IndexMap<String, Value>> {
        let mut names = IndexMap::new();
        let Some(workbook) = self.get_workbook()? else {
            return Ok(names);
        };
        if untangled(&workbook.tag) == "workbook"
            && let Attr::One(defined) = attr(&workbook, "definedNames")
            && has(defined, "definedName")
        {
            for name in each(defined, "definedName")? {
                let Some(key) = name.get("name") else {
                    return attr_error("NoneType", "replace");
                };
                names.insert(
                    key.replace("_xlnm.", "").to_lowercase(),
                    Value::string(cdata(name)),
                );
            }
        }
        Ok(names)
    }

    fn sheet_infos(&mut self, kind: &'static str, out: &OutRef) -> R<Vec<SheetInfo>> {
        let mut result = Vec::new();
        let workbook = self.get_workbook()?;
        let mut seen = std::collections::HashSet::new();
        let (_, dir, _) = self.get_workbook_path()?;
        let Some(workbook) = workbook else {
            return Ok(result);
        };
        if untangled(&workbook.tag) != "workbook" {
            return Ok(result);
        }
        let sheets = match attr(&workbook, "sheets") {
            Attr::One(sheets) => sheets,
            Attr::Many(_) => return attr_error("list", "sheet"),
            Attr::None => return raise("AttributeError", "'workbook' has no attribute 'sheets'"),
        };
        for element in each(sheets, "sheet")? {
            let r_id = element.get("r:id");
            let name = element.get("name");
            let (sheet_type, rel_path) = self.get_sheet_info(r_id)?;
            if let Some(rel_path) = rel_path {
                let path = format!("{dir}/{rel_path}");
                let key = name.map(str::to_owned);
                if sheet_type == Some(kind) && !seen.contains(&key) {
                    let sheet = Sheet::new(name.unwrap_or("None"), kind);
                    let xml = self.get_xml_file(&path, true)?;
                    result.push(SheetInfo { sheet, xml });
                    seen.insert(key);
                }
            } else {
                let line = format!(
                    "Sheet('{}') does not have a valid rId('{}')",
                    name.unwrap_or("None"),
                    r_id.unwrap_or("None")
                );
                out.borrow_mut().print(&line)?;
            }
        }
        Ok(result)
    }

    fn get_shared_strings(&mut self) -> R<Option<Vec<String>>> {
        if self.shared_strings.is_none() {
            let (_, dir, _) = self.get_workbook_path()?;
            let mut strings: Option<Vec<String>> = None;
            if let Some(content) = self.get_xml_file(&format!("{dir}/sharedStrings.xml"), false)?
                && untangled(&content.tag) == "sst"
                && has(&content, "si")
            {
                for item in each(&content, "si")? {
                    let list = strings.get_or_insert_with(Vec::new);
                    if has(item, "t") {
                        match attr(item, "t") {
                            Attr::One(t) => list.push(cdata(t)),
                            _ => return attr_error("list", "cdata"),
                        }
                    } else if let Attr::Many(runs) = attr(item, "r") {
                        // a single <r> indexes an Element by 0, which is None, so it adds nothing
                        if has(runs[0], "t") {
                            match attr(runs[0], "t") {
                                Attr::One(t) => list.push(cdata(t)),
                                _ => return attr_error("list", "cdata"),
                            }
                        }
                    }
                }
            }
            self.shared_strings = Some(strings);
        }
        Ok(self.shared_strings.clone().flatten())
    }

    fn string_at(&mut self, index: &str) -> R<String> {
        let strings = self.get_shared_strings()?;
        let index = Value::str(index).to_int()?;
        let Some(strings) = strings else {
            return raise("TypeError", "'NoneType' object is not subscriptable");
        };
        let length = strings.len() as i128;
        let at = if index < 0 { index + length } else { index };
        if at < 0 || at >= length {
            return index_error();
        }
        Ok(strings[at as usize].clone())
    }

    fn load_row_height(sheet: &SheetRef, row: &Element) {
        if let (Some(key), Some(height)) = (row.get("r"), row.get("ht")) {
            sheet
                .row_height
                .borrow_mut()
                .insert(key.to_owned(), height.to_owned());
        }
    }

    fn load_macro_cells(&mut self, sheet: &SheetRef, xml: &Element, names: &[String]) -> R<()> {
        // only an element under the root can be asked for, so a root by another name fails the same
        let body = sheet_body(xml)?;
        let data = one_or_list_error(body, "sheetData")?;
        if !has(data, "row") {
            return Ok(());
        }
        for row in each(data, "row")? {
            if (self.expired)() {
                return Err(Raised::Timeout);
            }
            Self::load_row_height(sheet, row);
            if !has(row, "c") {
                continue;
            }
            for element in each(row, "c")? {
                let mut formula_text = None;
                if has(element, "f") {
                    let formula = match attr(element, "f") {
                        Attr::One(formula) => formula,
                        _ => return attr_error("list", "get_attribute"),
                    };
                    if formula.get("bx") == Some("1") {
                        let text = cdata(formula);
                        if let Some(eq) = text.find('=')
                            && eq > 0
                        {
                            formula_text = Some(format!(
                                "=SET.NAME(\"{}\",{})",
                                &text[..eq],
                                &text[eq + 1..]
                            ));
                        }
                    } else {
                        formula_text = Some(format!("={}", cdata(formula)));
                    }
                }
                if let Some(text) = &mut formula_text {
                    for name in names {
                        if text
                            .to_lowercase()
                            .contains(&format!("{}!", name.to_lowercase()))
                        {
                            *text = sub_sheet_name(name, text)?;
                        }
                    }
                }
                let kind = element.get("t");
                let mut value_text = None;
                if has(element, "v") {
                    let value = match attr(element, "v") {
                        Attr::One(value) => cdata(value),
                        _ => return attr_error("list", "cdata"),
                    };
                    value_text = Some(if kind == Some("s") {
                        self.string_at(&value)?
                    } else {
                        value
                    });
                }
                let Some(location) = element.get("r") else {
                    if formula_text.as_deref().is_some_and(|t| !t.is_empty())
                        || value_text.as_deref().is_some_and(|t| !t.is_empty())
                    {
                        return attr_error("NoneType", "strip");
                    }
                    continue;
                };
                let filled = formula_text.as_deref().is_some_and(|t| !t.is_empty())
                    || value_text.as_deref().is_some_and(|t| !t.is_empty());
                if filled {
                    let mut cell = Cell::new(sheet);
                    let (_, column, row_number) = parse_cell_addr(location);
                    cell.column = column;
                    cell.row = row_number;
                    if kind != Some("str") {
                        cell.formula = formula_text;
                    }
                    cell.value = value_text.map_or(Value::None, Value::string);
                    cell.style = element.get("s").map(str::to_owned);
                    let cells = sheet.cells.borrow().clone();
                    cells
                        .borrow_mut()
                        .insert(location.to_owned(), Rc::new(RefCell::new(cell)));
                }
            }
        }
        Ok(())
    }

    fn load_worksheet_cells(&mut self, sheet: &SheetRef, xml: &Element) -> R<()> {
        if untangled(&xml.tag) != "worksheet" {
            return raise("AttributeError", "'None' has no attribute 'worksheet'");
        }
        let data = one_or_list_error(xml, "sheetData")?;
        if !has(data, "row") {
            return Ok(());
        }
        for row in each(data, "row")? {
            if (self.expired)() {
                return Err(Raised::Timeout);
            }
            Self::load_row_height(sheet, row);
            if !has(row, "c") {
                continue;
            }
            for element in each(row, "c")? {
                let mut formula_text = None;
                if has(element, "f") {
                    match attr(element, "f") {
                        Attr::One(formula) => formula_text = Some(format!("={}", cdata(formula))),
                        _ => {
                            return raise(
                                "TypeError",
                                "can only concatenate str (not \"list\") to str",
                            );
                        }
                    }
                }
                let mut value_text = None;
                if has(element, "v") {
                    let value = match attr(element, "v") {
                        Attr::One(value) => cdata(value),
                        _ => return attr_error("list", "cdata"),
                    };
                    value_text = Some(if element.get("t") == Some("s") {
                        self.string_at(&value)?
                    } else {
                        value
                    });
                }
                let Some(location) = element.get("r") else {
                    return attr_error("NoneType", "strip");
                };
                let mut cell = Cell::new(sheet);
                let (_, column, row_number) = parse_cell_addr(location);
                cell.column = column;
                cell.row = row_number;
                cell.formula = formula_text;
                cell.value = value_text.map_or(Value::None, Value::string);
                cell.style = element.get("s").map(str::to_owned);
                let cells = sheet.cells.borrow().clone();
                cells
                    .borrow_mut()
                    .insert(location.to_owned(), Rc::new(RefCell::new(cell)));
            }
        }
        Ok(())
    }

    fn set_default_height(sheet: &SheetRef, body: &Element) -> R<()> {
        if has(body, "sheetFormatPr") {
            let Attr::One(format) = attr(body, "sheetFormatPr") else {
                return attr_error("list", "get_attribute");
            };
            *sheet.default_height.borrow_mut() = format.get("defaultRowHeight").map(str::to_owned);
        }
        Ok(())
    }

    fn get_style(&mut self) -> R<Option<Rc<Element>>> {
        if self.style.is_none() {
            let kind = "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml";
            if let Some(path) = self.types.get(kind).cloned() {
                let Some(path) = path else {
                    return attr_error("NoneType", "startswith");
                };
                self.style = self.get_xml_file(&path, false)?;
            }
        }
        Ok(self.style.clone())
    }

    fn cell_info(&mut self, sheet: &SheetRef, col: &str, row: &str, info: &Value) -> R<CellInfo> {
        let address = format!("{col}{row}");
        let info_id = match info {
            Value::Int(id) => Some(*id),
            _ => None,
        };
        if info_id == Some(17) {
            let style = self.get_style();
            style?;
            let height = sheet.row_height.borrow().get(row).cloned();
            let (data, not_exist) = match height {
                Some(height) => (Some(height), false),
                None => (sheet.default_height.borrow().clone(), true),
            };
            let Some(data) = data else {
                return raise(
                    "TypeError",
                    "float() argument must be a string or a real number, not 'NoneType'",
                );
            };
            let number = Value::string(data).to_float()? * 4.0;
            if !number.is_finite() {
                return if number.is_nan() {
                    raise("ValueError", "cannot convert float NaN to integer")
                } else {
                    raise("OverflowError", "cannot convert float infinity to integer")
                };
            }
            return Ok((
                Value::Float(number.round_ties_even() / 4.0),
                not_exist,
                false,
            ));
        }
        let style = self.get_style()?;
        let none_style = || attr_error::<&Element>("NoneType", "styleSheet");
        let mut cell_format: Option<&Element> = None;
        let mut font: Option<&Element> = None;
        if let Some(cell) = sheet.cell(&address) {
            let style_index = cell.borrow().style.clone();
            if let Some(index) = style_index {
                let index = Value::string(index).to_int()?;
                let Some(style) = style.as_deref() else {
                    none_style()?;
                    return Ok((Value::None, false, false));
                };
                let sheet_style = one_or_none_style(style)?;
                cell_format = pick(one_or_list_error(sheet_style, "cellXfs")?, "xf", index)?;
                let Some(format) = cell_format else {
                    return attr_error("NoneType", "_attributes");
                };
                if let Some(font_id) = format.get("fontId") {
                    let font_id = Value::str(font_id).to_int()?;
                    font = pick(one_or_list_error(sheet_style, "fonts")?, "font", font_id)?;
                }
            }
        } else {
            let Some(style) = style.as_deref() else {
                none_style()?;
                return Ok((Value::None, false, false));
            };
            let sheet_style = one_or_none_style(style)?;
            for cell_style in each(one_or_list_error(sheet_style, "cellStyles")?, "cellStyle")? {
                if cell_style.get("name") == Some("Normal") {
                    let Some(xf_id) = cell_style.get("xfId") else {
                        return raise(
                            "TypeError",
                            "int() argument must be a string, a bytes-like object or a real number, not 'NoneType'",
                        );
                    };
                    let index = Value::str(xf_id).to_int()?;
                    let style_xfs = one_or_list_error(sheet_style, "cellStyleXfs")?;
                    cell_format = match attr(style_xfs, "xf") {
                        Attr::Many(_) => pick(style_xfs, "xf", index)?,
                        Attr::One(xf) => Some(xf),
                        Attr::None => {
                            return raise("AttributeError", "'cellStyleXfs' has no attribute 'xf'");
                        }
                    };
                    let Some(format) = cell_format else {
                        return attr_error("NoneType", "_attributes");
                    };
                    if let Some(font_id) = format.get("fontId") {
                        let font_id = Value::str(font_id).to_int()?;
                        font = pick(one_or_list_error(sheet_style, "fonts")?, "font", font_id)?;
                    }
                    break;
                }
            }
        }
        let mut data = Value::None;
        let mut not_implemented = false;
        let lower_key = |text: &str| repr_str(&text.to_lowercase());
        match info_id {
            Some(8) => {
                data = Value::Int(1);
                if let Some(format) = cell_format
                    && has(format, "alignment")
                {
                    let Attr::One(alignment) = attr(format, "alignment") else {
                        return attr_error("list", "get_attribute");
                    };
                    let Some(horizontal) = alignment.get("horizontal") else {
                        return attr_error("NoneType", "lower");
                    };
                    data = Value::Int(match horizontal.to_lowercase().as_str() {
                        "general" => 1,
                        "left" => 2,
                        "center" => 3,
                        "right" => 4,
                        "fill" => 5,
                        "justify" => 6,
                        "distributed" => 8,
                        _ => return raise("KeyError", lower_key(horizontal)),
                    });
                }
            }
            Some(19) => {
                if let Some(font) = font
                    && has(font, "sz")
                {
                    let Attr::One(size) = attr(font, "sz") else {
                        return attr_error("list", "get_attribute");
                    };
                    let value = size.get("val").map_or(Value::None, Value::str);
                    data = Value::Float(value.to_float()?);
                }
            }
            Some(24) => {
                let Some(font) = font else {
                    return attr_error("NoneType", "color");
                };
                let color = one_or_list_error(font, "color")?;
                data = match color.get("rgb") {
                    Some(rgb) => color_index(rgb)?,
                    None => Value::Int(1),
                };
            }
            Some(38) => {
                let Some(format) = cell_format else {
                    return attr_error("NoneType", "get_attribute");
                };
                let fill_id = format
                    .get("fillId")
                    .map_or(Value::None, Value::str)
                    .to_int()?;
                let Some(style) = style.as_deref() else {
                    return attr_error("NoneType", "styleSheet");
                };
                let sheet_style = one_or_none_style(style)?;
                let Some(fill) = pick(one_or_list_error(sheet_style, "fills")?, "fill", fill_id)?
                else {
                    return attr_error("NoneType", "patternFill");
                };
                let pattern = one_or_list_error(fill, "patternFill")?;
                data = Value::Int(0);
                if has(pattern, "fgColor") {
                    let Attr::One(foreground) = attr(pattern, "fgColor") else {
                        return attr_error("list", "get_attribute");
                    };
                    let Some(rgb) = foreground.get("rgb") else {
                        return raise("TypeError", "'NoneType' object is not subscriptable");
                    };
                    data = color_index(rgb)?;
                }
            }
            Some(50) => {
                let mut vertical = Some("bottom".to_owned());
                if let Some(format) = cell_format
                    && has(format, "alignment")
                {
                    let Attr::One(alignment) = attr(format, "alignment") else {
                        return attr_error("list", "get_attribute");
                    };
                    vertical = alignment.get("vertical").map(str::to_owned);
                }
                let Some(vertical) = vertical else {
                    return attr_error("NoneType", "lower");
                };
                data = Value::Int(match vertical.to_lowercase().as_str() {
                    "top" => 1,
                    "center" => 2,
                    "bottom" => 3,
                    "justify" => 4,
                    "distributed" => 5,
                    _ => return raise("KeyError", lower_key(&vertical)),
                });
            }
            _ => not_implemented = true,
        }
        Ok((data, false, not_implemented))
    }
}

fn one_or_list_error<'a>(element: &'a Element, name: &str) -> R<&'a Element> {
    one(element, name)
}

fn one_or_none_style(style: &Element) -> R<&Element> {
    if untangled(&style.tag) == "styleSheet" {
        Ok(style)
    } else {
        raise("AttributeError", "'None' has no attribute 'styleSheet'")
    }
}

/// `parent.name[index]`: a list's item, or for one element its `__getitem__`, which asks its attributes
/// for that number and gets None.
fn pick<'a>(parent: &'a Element, name: &str, index: i128) -> R<Option<&'a Element>> {
    match attr(parent, name) {
        Attr::One(_) => Ok(None),
        Attr::Many(list) => {
            let length = list.len() as i128;
            let at = if index < 0 { index + length } else { index };
            if at < 0 || at >= length {
                return index_error();
            }
            Ok(Some(list[at as usize]))
        }
        Attr::None => raise(
            "AttributeError",
            format!("'{}' has no attribute '{name}'", untangled(&parent.tag)),
        ),
    }
}

/// `get_color_index`, with its table.
fn color_index(rgba: &str) -> R<Value> {
    const COLORS: &[(u8, u8, u8, i128)] = &[
        (0, 0, 0, 1),
        (255, 255, 255, 2),
        (255, 0, 0, 3),
        (0, 255, 0, 4),
        (0, 0, 255, 5),
        (255, 255, 0, 6),
        (255, 0, 255, 7),
        (0, 255, 255, 8),
        (128, 0, 0, 9),
        (0, 128, 0, 10),
        (0, 0, 128, 11),
        (128, 128, 0, 12),
        (128, 0, 128, 13),
        (0, 128, 128, 14),
        (192, 192, 192, 15),
        (128, 128, 128, 16),
        (153, 153, 255, 17),
        (153, 51, 102, 18),
        (255, 255, 204, 19),
        (204, 255, 255, 20),
        (102, 0, 102, 21),
        (255, 128, 128, 22),
        (0, 102, 204, 23),
        (204, 204, 255, 24),
        (0, 204, 255, 33),
        (204, 255, 204, 35),
        (255, 255, 153, 36),
        (153, 204, 255, 37),
        (255, 153, 204, 38),
        (204, 153, 255, 39),
        (255, 204, 153, 40),
        (51, 102, 255, 41),
        (51, 204, 204, 42),
        (153, 204, 0, 43),
        (255, 204, 0, 44),
        (255, 153, 0, 45),
        (255, 102, 0, 46),
        (102, 102, 153, 47),
        (150, 150, 150, 48),
        (0, 51, 102, 49),
        (51, 153, 102, 50),
        (0, 51, 0, 51),
        (51, 51, 0, 52),
        (153, 51, 0, 53),
        (51, 51, 153, 55),
        (51, 51, 51, 56),
    ];
    let chars: Vec<char> = rgba.chars().collect();
    let part = |from: usize| -> R<u8> {
        let text: String = chars.iter().skip(from).take(2).collect();
        match u8::from_str_radix(&text, 16) {
            Ok(n) => Ok(n),
            Err(_) => raise(
                "ValueError",
                format!(
                    "invalid literal for int() with base 16: {}",
                    repr_str(&format!("0x{text}"))
                ),
            ),
        }
    };
    let (r, g, b) = (part(2)?, part(4)?, part(6)?);
    Ok(COLORS
        .iter()
        .find(|c| (c.0, c.1, c.2) == (r, g, b))
        .map_or(Value::None, |c| Value::Int(c.3)))
}

fn sheet_body(xml: &Element) -> R<&Element> {
    match untangled(&xml.tag).as_str() {
        "xm_macrosheet" | "worksheet" => Ok(xml),
        _ => raise("AttributeError", "'None' has no attribute 'worksheet'"),
    }
}

/// `re.sub('{}\!'.format(name), "'{}'!".format(name), text)`. A sheet's name is a pattern there, so one
/// that isn't a valid expression raises as Python's would, though in the regex crate's words.
fn sub_sheet_name(name: &str, text: &str) -> R<String> {
    let pattern = format!("{name}\\!");
    match fancy_regex::Regex::new(&pattern) {
        Ok(regex) => Ok(regex
            .replace_all(text, fancy_regex::NoExpand(&format!("'{name}'!")))
            .into_owned()),
        Err(error) => raise("PatternError", error.to_string()),
    }
}

enum Kind {
    Xlsm(Box<Xlsm>),
    Xls(Box<XlsBook>),
    Xlsb(Box<XlsbBook>),
}

struct XlsBook {
    book: ace_xlrd::Book,
}

struct XlsbBook {
    package: XlsbZip,
    workbook: ace_xlsb::Workbook,
    expired: Rc<dyn Fn() -> bool>,
}

struct XlsbZip {
    data: Vec<u8>,
}

impl ace_xlsb::Package for XlsbZip {
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, ace_xlsb::XlError> {
        let zip = ZipFile::new(&self.data).map_err(to_xlsb)?;
        if !zip.contains(name) {
            return Ok(None);
        }
        zip.read(name).map(Some).map_err(to_xlsb)
    }

    fn rels_xml(&self, name: &str) -> Result<Option<ace_xlsb::RelsXml>, ace_xlsb::XlError> {
        let zip = ZipFile::new(&self.data).map_err(to_xlsb)?;
        if !zip.contains(name) {
            return Ok(None);
        }
        let data = zip.read(name).map_err(to_xlsb)?;
        let text = decode_utf8(&data).map_err(|raised| match raised {
            Raised::Exception { kind, message } => ace_xlsb::XlError::new(kind, message),
            _ => ace_xlsb::XlError::new("PassTimeout", ""),
        })?;
        let root = pyxml::fromstring(text.as_bytes()).map_err(to_xlsb)?;
        let tag = "{http://schemas.openxmlformats.org/package/2006/relationships}Relationship";
        let relationships = root
            .iter_tag(tag)
            .into_iter()
            .filter(|element| !std::ptr::eq(*element, &root))
            .map(|element| ace_xlsb::Rel {
                id: element.get("Id").map(str::to_owned),
                target: element.get("Target").map(str::to_owned),
                rel_type: element.get("Type").map(str::to_owned),
            })
            .collect();
        Ok(Some(ace_xlsb::RelsXml {
            has_children: !root.children.is_empty(),
            relationships,
        }))
    }
}

fn to_xlsb(error: PyErr) -> ace_xlsb::XlError {
    ace_xlsb::XlError::new(&error.kind, error.message)
}

/// `ExcelWrapper`, with what each format does lazily done lazily, so that what raises raises when Python's does.
pub struct Wrapper {
    kind: RefCell<Kind>,
    pub workbook_name: Option<String>,
    names: RefCell<Option<Names>>,
    macrosheets: RefCell<Option<IndexMap<String, SheetRef>>>,
    worksheets: RefCell<Option<IndexMap<String, SheetRef>>>,
    out: OutRef,
    is_xls: bool,
}

fn from_xls_value(value: &ace_xlrd::CellValue) -> Value {
    match value {
        ace_xlrd::CellValue::None => Value::None,
        ace_xlrd::CellValue::Text(text) => Value::Str(Rc::from(&**text)),
        ace_xlrd::CellValue::Float(f) => Value::Float(*f),
        ace_xlrd::CellValue::Int(i) => Value::Int(i128::from(*i)),
    }
}

fn from_xlsb_value(value: &ace_xlsb::CellValue) -> Value {
    match value {
        ace_xlsb::CellValue::None => Value::None,
        ace_xlsb::CellValue::Text(text) => Value::str(text),
        ace_xlsb::CellValue::Float(f) => Value::Float(*f),
        ace_xlsb::CellValue::Int(i) => Value::Int(i128::from(*i)),
        ace_xlsb::CellValue::Bool(b) => Value::Bool(*b),
        ace_xlsb::CellValue::Error(text) => Value::Object(Rc::from(text.as_str())),
    }
}

impl Wrapper {
    pub fn xlsm(
        data: Vec<u8>,
        name: &str,
        out: OutRef,
        expired: Rc<dyn Fn() -> bool>,
    ) -> R<Wrapper> {
        Ok(Wrapper::of(
            Kind::Xlsm(Box::new(Xlsm::new(data, expired)?)),
            Some(name.to_owned()),
            out,
            false,
        ))
    }

    pub fn xls(
        data: Vec<u8>,
        name: &str,
        out: OutRef,
        expired: Rc<dyn Fn() -> bool>,
    ) -> R<Wrapper> {
        let mut log = String::new();
        let opened = ace_xlrd::Book::open(&data, &mut log, &*expired);
        out.borrow_mut().text.push_str(&log);
        let book = opened.map_err(|error| from_xl(error.kind, error.message))?;
        Ok(Wrapper::of(
            Kind::Xls(Box::new(XlsBook { book })),
            Some(name.to_owned()),
            out,
            true,
        ))
    }

    pub fn xlsb(data: Vec<u8>, out: OutRef, expired: Rc<dyn Fn() -> bool>) -> R<Wrapper> {
        let package = XlsbZip { data };
        let mut log = String::new();
        let opened = ace_xlsb::Workbook::open(&package, &mut log, &*expired);
        out.borrow_mut().text.push_str(&log);
        let workbook = opened.map_err(|error| from_xl(error.kind, error.message))?;
        Ok(Wrapper::of(
            Kind::Xlsb(Box::new(XlsbBook {
                package,
                workbook,
                expired,
            })),
            None,
            out,
            false,
        ))
    }

    fn of(kind: Kind, workbook_name: Option<String>, out: OutRef, is_xls: bool) -> Wrapper {
        Wrapper {
            kind: RefCell::new(kind),
            workbook_name,
            names: RefCell::new(None),
            macrosheets: RefCell::new(None),
            worksheets: RefCell::new(None),
            out,
            is_xls,
        }
    }

    /// The sheets loaded so far. For dropping them: nothing here loads one.
    pub fn loaded_sheets(&self) -> Vec<SheetRef> {
        let mut sheets = Vec::new();
        for loaded in [&self.macrosheets, &self.worksheets] {
            if let Some(map) = &*loaded.borrow() {
                sheets.extend(map.values().cloned());
            }
        }
        sheets
    }

    /// Whether `replace_nonprintable_chars` exists: only XLSWrapper2 has it.
    pub fn replaces_nonprintable(&self) -> bool {
        self.is_xls
    }

    pub fn get_workbook_name(&self) -> R<String> {
        match &self.workbook_name {
            Some(name) => Ok(name.clone()),
            None => attr_error("XLSBWrapper", "xlsm_workbook_name"),
        }
    }

    pub fn get_defined_names(&self) -> R<Names> {
        if let Some(names) = &*self.names.borrow() {
            return Ok(names.clone());
        }
        let names = match &mut *self.kind.borrow_mut() {
            // Python assigns the dict before it fills it, so a failure leaves it empty and not asked again
            Kind::Xlsm(xlsm) => {
                *self.names.borrow_mut() = Some(Rc::new(RefCell::new(IndexMap::new())));
                xlsm.defined_names()?
            }
            Kind::Xls(xls) => {
                *self.names.borrow_mut() = Some(Rc::new(RefCell::new(IndexMap::new())));
                xls.book
                    .defined_names()
                    .map_err(|error| from_xl(error.kind, error.message))?
                    .into_iter()
                    .map(|(name, value)| (name, xls_name(&value)))
                    .collect()
            }
            Kind::Xlsb(xlsb) => xlsb
                .workbook
                .defined_names()
                .map_err(|error| from_xl(error.kind.clone(), error.message.clone()))?
                .into_iter()
                .map(|(name, (key, formula))| {
                    let pair = vec![Value::string(key), xlsb_formula(formula)];
                    (name, Value::Tuple(Rc::new(pair)))
                })
                .collect(),
        };
        let names = Rc::new(RefCell::new(names));
        *self.names.borrow_mut() = Some(names.clone());
        Ok(names)
    }

    /// `get_defined_name(name, full_match)`.
    pub fn get_defined_name(&self, name: &str, full_match: bool) -> R<Value> {
        let names = self.get_defined_names()?;
        let names = names.borrow();
        let lower = name.to_lowercase();
        let key = if self.is_xls {
            lower.replace('[', "")
        } else {
            lower
        };
        let mut result = Value::List(Rc::new(Vec::new()));
        let xlsb = matches!(&*self.kind.borrow(), Kind::Xlsb(_));
        if full_match {
            if let Some(found) = names.get(&key) {
                result = if xlsb {
                    Value::List(Rc::new(vec![found.clone()]))
                } else {
                    found.clone()
                };
            }
        } else {
            let mut items = Vec::new();
            for (defined, address) in names.iter() {
                if defined.starts_with(&key) {
                    if xlsb {
                        items.push(address.clone());
                    } else {
                        items.push(Value::Tuple(Rc::new(vec![
                            Value::str(defined),
                            address.clone(),
                        ])));
                    }
                }
            }
            result = Value::List(Rc::new(items));
        }
        if self.is_xls
            && let Value::List(items) = &result
            && items.is_empty()
        {
            // JohnLaTwC's: the name's characters in order, with anything between them
            let mut items = Vec::new();
            for (defined, address) in names.iter() {
                let chars: Vec<char> = defined.chars().collect();
                let mut last: i64 = 0;
                let mut matched = true;
                for c in key.chars() {
                    let start = if last < 0 {
                        (chars.len() as i64 + last).max(0) as usize
                    } else {
                        last as usize
                    };
                    match chars.iter().skip(start).position(|x| *x == c) {
                        Some(at) => last = (start + at) as i64,
                        None => {
                            matched = false;
                            last = -1;
                        }
                    }
                }
                if matched {
                    items.push(Value::Tuple(Rc::new(vec![
                        Value::str(defined),
                        address.clone(),
                    ])));
                }
            }
            result = Value::List(Rc::new(items));
        }
        Ok(result)
    }

    pub fn get_macrosheets(&self) -> R<IndexMap<String, SheetRef>> {
        if let Some(sheets) = &*self.macrosheets.borrow() {
            return Ok(sheets.clone());
        }
        // Python assigns the dict before it fills it, so what's loaded stays, and it isn't loaded again
        *self.macrosheets.borrow_mut() = Some(IndexMap::new());
        let mut kind = self.kind.borrow_mut();
        match &mut *kind {
            Kind::Xlsm(xlsm) => {
                let infos = xlsm.sheet_infos("Macrosheet", &self.out)?;
                let names: Vec<String> = infos.iter().map(|i| i.sheet.name.clone()).collect();
                for info in infos {
                    if let Some(xml) = &info.xml {
                        xlsm.load_macro_cells(&info.sheet, xml, &names)?;
                        Xlsm::set_default_height(&info.sheet, sheet_body(xml)?)?;
                    }
                    self.add_macrosheet(info.sheet);
                }
            }
            Kind::Xls(xls) => {
                for (index, info) in xls.book.sheets().iter().enumerate() {
                    if info.boundsheet_type == ace_xlrd::SheetType::Macrosheet {
                        let sheet = Sheet::new(&info.name, "Macrosheet");
                        load_xls_cells(&xls.book, index, &sheet, &self.out);
                        self.add_macrosheet(sheet);
                    }
                }
            }
            Kind::Xlsb(xlsb) => {
                for info in xlsb.workbook.sheets() {
                    if info.sheet_type.as_deref() == Some("macrosheet") {
                        let sheet =
                            Sheet::new(info.name.as_deref().unwrap_or("None"), "macrosheet");
                        load_xlsb_cells(xlsb, info.name.as_deref(), &sheet, &self.out)?;
                        self.add_macrosheet(sheet);
                    }
                }
            }
        }
        drop(kind);
        Ok(self.macrosheets.borrow().clone().unwrap_or_default())
    }

    fn add_macrosheet(&self, sheet: SheetRef) {
        if let Some(sheets) = &mut *self.macrosheets.borrow_mut() {
            sheets.insert(sheet.name.clone(), sheet);
        }
    }

    pub fn get_worksheets(&self) -> R<IndexMap<String, SheetRef>> {
        if let Some(sheets) = &*self.worksheets.borrow() {
            return Ok(sheets.clone());
        }
        *self.worksheets.borrow_mut() = Some(IndexMap::new());
        let mut kind = self.kind.borrow_mut();
        let add = |sheet: SheetRef| {
            if let Some(sheets) = &mut *self.worksheets.borrow_mut() {
                sheets.insert(sheet.name.clone(), sheet);
            }
        };
        match &mut *kind {
            Kind::Xlsm(xlsm) => {
                for info in xlsm.sheet_infos("Worksheet", &self.out)? {
                    let Some(xml) = &info.xml else {
                        return attr_error("NoneType", "worksheet");
                    };
                    xlsm.load_worksheet_cells(&info.sheet, xml)?;
                    Xlsm::set_default_height(&info.sheet, xml)?;
                    add(info.sheet);
                }
            }
            Kind::Xls(xls) => {
                for (index, info) in xls.book.sheets().iter().enumerate() {
                    if info.boundsheet_type == ace_xlrd::SheetType::Worksheet {
                        let sheet = Sheet::new(&info.name, "Worksheet");
                        load_xls_cells(&xls.book, index, &sheet, &self.out);
                        add(sheet);
                    }
                }
            }
            Kind::Xlsb(xlsb) => {
                for info in xlsb.workbook.sheets() {
                    if info.sheet_type.as_deref() == Some("worksheet") {
                        let sheet = Sheet::new(info.name.as_deref().unwrap_or("None"), "worksheet");
                        load_xlsb_cells(xlsb, info.name.as_deref(), &sheet, &self.out)?;
                        add(sheet);
                    }
                }
            }
        }
        drop(kind);
        Ok(self.worksheets.borrow().clone().unwrap_or_default())
    }

    /// `get_cell_info(sheet_name, col, row, info_type_id)`.
    pub fn get_cell_info(
        &self,
        sheet_name: &str,
        col: Option<&str>,
        row: Option<&str>,
        info: &Value,
    ) -> R<CellInfo> {
        match &mut *self.kind.borrow_mut() {
            Kind::Xlsm(xlsm) => {
                let sheets = self.macrosheets.borrow();
                let Some(sheet) = sheets.as_ref().and_then(|s| s.get(sheet_name)).cloned() else {
                    return raise("KeyError", repr_str(sheet_name));
                };
                drop(sheets);
                let Some(col) = col else {
                    return raise(
                        "TypeError",
                        "unsupported operand type(s) for +: 'NoneType' and 'str'",
                    );
                };
                xlsm.cell_info(&sheet, col, row.unwrap_or("None"), info)
            }
            Kind::Xls(xls) => {
                let Some(col) = col else {
                    return raise("TypeError", "'NoneType' object is not reversible");
                };
                let info_id = super::value::float_to_int(info.to_float()?)?;
                let (data, not_exist, not_implemented) = xls
                    .book
                    .get_cell_info(sheet_name, col, row.unwrap_or("None"), info_id as i64)
                    .map_err(|error| from_xl(error.kind, error.message))?;
                Ok((from_xls_value(&data), not_exist, not_implemented))
            }
            Kind::Xlsb(_) => Ok((Value::None, false, true)),
        }
    }
}

/// A defined name's value. What isn't a str, a number or a list only ever reaches `str()`, which is what
/// an Object holds.
fn xls_name(value: &ace_xlrd::NameValue) -> Value {
    match value {
        ace_xlrd::NameValue::Text(text) => Value::str(text),
        ace_xlrd::NameValue::Num(n) => Value::Float(*n),
        ace_xlrd::NameValue::Int(i) => Value::Int(i128::from(*i)),
        ace_xlrd::NameValue::None => Value::None,
        ace_xlrd::NameValue::Arr(items) => Value::List(Rc::new(
            items
                .iter()
                .map(|item| match item {
                    ace_xlrd::ArrItem::Num(n) => Value::Float(*n),
                    ace_xlrd::ArrItem::Text(text) => Value::str(text),
                })
                .collect(),
        )),
        other => Value::Object(Rc::from(other.py_str())),
    }
}

fn xlsb_formula(formula: Option<String>) -> Value {
    formula.map_or(Value::None, Value::string)
}

fn load_xls_cells(book: &ace_xlrd::Book, index: usize, sheet: &SheetRef, out: &OutRef) {
    let mut log = String::new();
    let cells = book.load_cells(index, &mut log);
    out.borrow_mut().text.push_str(&log);
    let store = sheet.cells.borrow().clone();
    let mut store = store.borrow_mut();
    for loaded in cells {
        let mut cell = Cell::new(sheet);
        cell.row = Some(loaded.row.to_string());
        cell.column = Some(loaded.column);
        cell.formula = loaded.formula;
        cell.value = from_xls_value(&loaded.value);
        if let Ok(address) = cell.local_address() {
            store.insert(address, Rc::new(RefCell::new(cell)));
        }
    }
}

fn load_xlsb_cells(xlsb: &XlsbBook, name: Option<&str>, sheet: &SheetRef, out: &OutRef) -> R<()> {
    let mut log = String::new();
    let cells = xlsb
        .workbook
        .load_cells(&xlsb.package, name, &mut log, &*xlsb.expired);
    out.borrow_mut().text.push_str(&log);
    let cells = cells.map_err(|error| from_xl(error.kind, error.message))?;
    let store = sheet.cells.borrow().clone();
    let mut store = store.borrow_mut();
    for loaded in cells {
        let mut cell = Cell::new(sheet);
        cell.row = Some(loaded.row.to_string());
        cell.column = Some(loaded.column);
        cell.formula = loaded.formula;
        cell.value = from_xlsb_value(&loaded.value);
        if let Ok(address) = cell.local_address() {
            store.insert(address, Rc::new(RefCell::new(cell)));
        }
    }
    Ok(())
}

/// A deadline a wrapper polls. Timers aren't available in a task, so this is a clock read.
pub fn expired_at(deadline: Option<Instant>) -> Rc<dyn Fn() -> bool> {
    Rc::new(move || deadline.is_some_and(|at| Instant::now() >= at))
}
