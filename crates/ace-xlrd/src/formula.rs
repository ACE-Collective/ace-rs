//! formula.py: evaluate_name_formula, decompile_formula, dump_formula and the name helpers.

use crate::book::Loader;
use crate::py::{
    R, assertion, byte_at, err, f64_at, float_repr, hex_char_dump, i16_at, list_index_error, need,
    py_index, repr_bytes, repr_str, slice, span, u8_at, u16_at, unpack_string_update_pos,
    unpack_unicode_update_pos, xlrd_err,
};
use crate::pyval::{self, ArrItem, PyVal, Ref3D};
use crate::tables::FUNC_DEFS;

pub(crate) const O_BOOL: i8 = 3;
pub(crate) const O_ERR: i8 = 4;
const O_MSNG: i8 = 5;
pub(crate) const O_NUM: i8 = 2;
pub(crate) const O_REF: i8 = -1;
pub(crate) const O_REL: i8 = -2;
pub(crate) const O_STRG: i8 = 1;
const O_UNK: i8 = 0;
pub(crate) const O_ARR: i8 = 6;

const FMLA_TYPE_CELL: u8 = 1;
const FMLA_TYPE_SHARED: u8 = 2;
const FMLA_TYPE_COND_FMT: u8 = 8;
const FMLA_TYPE_DATA_VAL: u8 = 16;
const ALL_FMLA_TYPES: u8 = 63;

const LEAF_RANK: i32 = 90;
const FUNC_RANK: i32 = 90;
const STACK_ALARM_LEVEL: i32 = 5;
const STACK_PANIC_LEVEL: i32 = 10;

const SZTAB0: [i32; 64] = [
    -2, 4, 4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -2, -1, 8, 4, 2, 2,
    3, 9, 8, 2, 3, 8, 4, 7, 5, 5, 5, 2, 4, 7, 4, 7, 2, 2, -2, -2, -2, -2, -2, -2, -2, -2, 3, -2,
    -2, -2, -2, -2, -2, -2,
];
const SZTAB1: [i32; 64] = [
    -2, 5, 5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -2, -1, 11, 5, 2, 2,
    3, 9, 9, 2, 3, 11, 4, 7, 7, 7, 7, 3, 4, 7, 4, 7, 3, 3, -2, -2, -2, -2, -2, -2, -2, -2, 3, -2,
    -2, -2, -2, -2, -2, -2,
];
const SZTAB2: [i32; 64] = [
    -2, 5, 5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -2, -1, 11, 5, 2, 2,
    3, 9, 9, 3, 4, 11, 4, 7, 7, 7, 7, 3, 4, 7, 4, 7, 3, 3, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2,
];
const SZTAB3: [i32; 64] = [
    -2, 5, 5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -2, -1, -2, -2, 2, 2,
    3, 9, 9, 3, 4, 15, 4, 7, 7, 7, 7, 3, 4, 7, 4, 7, 3, 3, -2, -2, -2, -2, -2, -2, -2, -2, -2, 25,
    18, 21, 18, 21, -2, -2,
];
const SZTAB4: [i32; 64] = [
    -2, 5, 5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -2, -2, 2, 2,
    3, 9, 9, 3, 4, 5, 5, 9, 7, 7, 7, 3, 5, 9, 5, 9, 3, 3, -2, -2, -2, -2, -2, -2, -2, -2, -2, 7, 7,
    11, 7, 11, -2, -2,
];

const ONAMES: [&str; 64] = [
    "Unk00",
    "Exp",
    "Tbl",
    "Add",
    "Sub",
    "Mul",
    "Div",
    "Power",
    "Concat",
    "LT",
    "LE",
    "EQ",
    "GE",
    "GT",
    "NE",
    "Isect",
    "List",
    "Range",
    "Uplus",
    "Uminus",
    "Percent",
    "Paren",
    "MissArg",
    "Str",
    "Extended",
    "Attr",
    "Sheet",
    "EndSheet",
    "Err",
    "Bool",
    "Int",
    "Num",
    "Array",
    "Func",
    "FuncVar",
    "Name",
    "Ref",
    "Area",
    "MemArea",
    "MemErr",
    "MemNoMem",
    "MemFunc",
    "RefErr",
    "AreaErr",
    "RefN",
    "AreaN",
    "MemAreaN",
    "MemNoMemN",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "FuncCE",
    "NameX",
    "Ref3d",
    "Area3d",
    "RefErr3d",
    "AreaErr3d",
    "",
    "",
];

fn sztab(bv: i32) -> &'static [i32; 64] {
    match bv {
        20 | 21 => &SZTAB0,
        30 => &SZTAB1,
        40 | 45 => &SZTAB2,
        50 | 70 => &SZTAB3,
        _ => &SZTAB4,
    }
}

fn token_size(tab: &[i32; 64], opx: usize) -> i64 {
    i64::from(tab.get(opx).copied().unwrap_or(-2))
}

fn oname(opx: usize) -> &'static str {
    ONAMES.get(opx).copied().unwrap_or("")
}

fn token_not_allowed(opx: usize) -> u8 {
    let shared_etc = FMLA_TYPE_SHARED + FMLA_TYPE_COND_FMT + FMLA_TYPE_DATA_VAL;
    match opx {
        0x01 | 0x02 => ALL_FMLA_TYPES - FMLA_TYPE_CELL,
        0x0F | 0x10 | 0x11 | 0x20 | 0x39 | 0x3A | 0x3B => shared_etc,
        0x23 => FMLA_TYPE_SHARED,
        0x2C | 0x2D => FMLA_TYPE_CELL + 4,
        _ => 0,
    }
}

fn is_error_opcode(opcode: u8) -> bool {
    matches!(opcode, 0x07 | 0x08 | 0x0A | 0x0B | 0x1C | 0x1D | 0x2F)
}

fn func_def(index: i64) -> Option<(&'static str, i64, i64)> {
    let k = u32::try_from(index).ok()?;
    FUNC_DEFS
        .binary_search_by_key(&k, |e| e.0)
        .ok()
        .and_then(|i| FUNC_DEFS.get(i))
        .map(|e| (e.1, e.2, e.3))
}

fn formula_error(message: impl Into<String>) -> crate::XlError {
    err("FormulaError", message)
}

fn error_text(code: u8) -> Option<&'static str> {
    Some(match code {
        0x00 => "#NULL!",
        0x07 => "#DIV/0!",
        0x0F => "#VALUE!",
        0x17 => "#REF!",
        0x1D => "#NAME?",
        0x24 => "#NUM!",
        0x2A => "#N/A",
        _ => return None,
    })
}

/// formula.Operand. `bare` is the int `oERR` that tRange pushes in place of an Operand: every
/// attribute read of it is an AttributeError.
#[derive(Clone)]
pub(crate) struct Operand {
    pub(crate) kind: i8,
    pub(crate) value: Option<PyVal>,
    pub(crate) rank: i32,
    pub(crate) text: String,
    pub(crate) bare: bool,
}

impl Operand {
    fn new(kind: i8, rank: i32, text: impl Into<String>) -> Self {
        Operand {
            kind,
            value: None,
            rank,
            text: text.into(),
            bare: false,
        }
    }

    fn with_value(kind: i8, value: PyVal, rank: i32, text: impl Into<String>) -> Self {
        Operand {
            kind,
            value: Some(value),
            rank,
            text: text.into(),
            bare: false,
        }
    }

    fn unk() -> Self {
        Operand::new(O_UNK, 0, "?")
    }

    fn err_opnd() -> Self {
        Operand::new(O_ERR, 0, "?")
    }

    fn bare_err() -> Self {
        Operand {
            kind: O_ERR,
            value: None,
            rank: 0,
            text: String::new(),
            bare: true,
        }
    }

    /// Read of an attribute: fails on the bare int.
    pub(crate) fn attr(&self, name: &str) -> R<&Self> {
        if self.bare {
            Err(err(
                "AttributeError",
                format!("'int' object has no attribute '{name}'"),
            ))
        } else {
            Ok(self)
        }
    }

    fn repr(&self) -> String {
        if self.bare {
            return O_ERR.to_string();
        }
        let kind = match self.kind {
            -2 => "oREL",
            -1 => "oREF",
            0 => "oUNK",
            1 => "oSTRG",
            2 => "oNUM",
            3 => "oBOOL",
            4 => "oERR",
            5 => "oMSNG",
            6 => "oARR",
            _ => "?Unknown kind?",
        };
        let value = self.value.as_ref().map_or("None".to_string(), PyVal::repr);
        format!(
            "Operand(kind={kind}, value={value}, text={})",
            repr_str(&self.text)
        )
    }
}

fn stack_repr(stack: &[Operand]) -> String {
    let parts: Vec<String> = stack.iter().map(Operand::repr).collect();
    format!("[{}]", parts.join(", "))
}

/// book.Name.
pub(crate) struct Name<'a> {
    pub(crate) name: String,
    option_flags: u16,
    func: u16,
    vbasic: u16,
    pub(crate) macro_: u16,
    complex: u16,
    builtin: u16,
    funcgroup: u16,
    pub(crate) binary: u16,
    hidden: u16,
    pub(crate) extn_sheet_num: i64,
    pub(crate) excel_sheet_index: i64,
    name_index: i64,
    pub(crate) scope: i64,
    pub(crate) raw_formula: &'a [u8],
    basic_formula_len: i64,
    pub(crate) evaluated: bool,
    stack: Vec<Operand>,
    any_rel: bool,
    any_err: i64,
}

impl<'a> Name<'a> {
    pub(crate) fn new(
        name: String,
        option_flags: u16,
        extn_sheet_num: i64,
        excel_sheet_index: i64,
        name_index: i64,
        raw_formula: &'a [u8],
        basic_formula_len: i64,
    ) -> Self {
        Name {
            name,
            option_flags,
            hidden: option_flags & 1,
            func: (option_flags & 2) >> 1,
            vbasic: (option_flags & 4) >> 2,
            macro_: (option_flags & 8) >> 3,
            complex: (option_flags & 0x10) >> 4,
            builtin: (option_flags & 0x20) >> 5,
            funcgroup: (option_flags & 0xFC0) >> 6,
            binary: (option_flags & 0x1000) >> 12,
            extn_sheet_num,
            excel_sheet_index,
            name_index,
            scope: -1,
            raw_formula,
            basic_formula_len,
            evaluated: false,
            stack: Vec::new(),
            any_rel: false,
            any_err: 0,
        }
    }

    /// nobj.result.
    pub(crate) fn result(&self) -> Option<&Operand> {
        if self.evaluated && self.stack.len() == 1 {
            self.stack.first()
        } else {
            None
        }
    }

    /// BaseObject.dump. The `book` line holds an address Python doesn't keep stable.
    fn dump(&self, log: &mut String, header: &str, footer: &str) {
        log.push_str(header);
        log.push('\n');
        let mut line = |k: &str, v: String| log.push_str(&format!("{k}: {v}\n"));
        if self.evaluated {
            line("any_err", self.any_err.to_string());
            line("any_external", "0".to_string());
            line("any_rel", py_bool(self.any_rel));
        }
        line("basic_formula_len", self.basic_formula_len.to_string());
        line("binary", self.binary.to_string());
        line("book", "<xlrd2.book.Book object>".to_string());
        line("builtin", self.builtin.to_string());
        line("complex", self.complex.to_string());
        line("evaluated", i32::from(self.evaluated).to_string());
        line("excel_sheet_index", self.excel_sheet_index.to_string());
        line("extn_sheet_num", self.extn_sheet_num.to_string());
        line("func", self.func.to_string());
        line("funcgroup", self.funcgroup.to_string());
        line("hidden", self.hidden.to_string());
        line("macro", self.macro_.to_string());
        line("name", crate::py::ascii_str(&self.name));
        line("name_index", self.name_index.to_string());
        line("option_flags", self.option_flags.to_string());
        line("raw_formula", repr_bytes(self.raw_formula));
        if self.evaluated {
            line(
                "result",
                self.result()
                    .map_or("None".to_string(), |r| crate::py::ascii_str_repr(&r.repr())),
            );
        }
        line("scope", self.scope.to_string());
        if self.evaluated {
            line("stack", crate::py::ascii_str_repr(&stack_repr(&self.stack)));
        }
        line("vbasic", self.vbasic.to_string());
        log.push_str(footer);
        log.push('\n');
    }
}

fn py_bool(b: bool) -> String {
    if b { "True" } else { "False" }.to_string()
}

type Addr = (i64, i64, i64, i64);

fn none_op() -> crate::XlError {
    err(
        "TypeError",
        "unsupported operand type(s) for -=: 'int' and 'NoneType'",
    )
}

fn adjust_biff8(
    rowval: i64,
    colval: i64,
    reldelta: bool,
    browx: Option<i64>,
    bcolx: Option<i64>,
) -> Addr {
    let row_rel = (colval >> 15) & 1;
    let col_rel = (colval >> 14) & 1;
    let mut rowx = rowval;
    let mut colx = colval & 0xff;
    if reldelta {
        if row_rel != 0 && rowx >= 32768 {
            rowx -= 65536;
        }
        if col_rel != 0 && colx >= 128 {
            colx -= 256;
        }
    } else {
        if row_rel != 0 {
            rowx -= browx.unwrap_or(0);
        }
        if col_rel != 0 {
            colx -= bcolx.unwrap_or(0);
        }
    }
    (rowx, colx, row_rel, col_rel)
}

fn adjust_le7(
    rowval: i64,
    colval: i64,
    reldelta: bool,
    browx: Option<i64>,
    bcolx: Option<i64>,
) -> R<Addr> {
    let row_rel = (rowval >> 15) & 1;
    let col_rel = (rowval >> 14) & 1;
    let mut rowx = rowval & 0x3fff;
    let mut colx = colval;
    if reldelta {
        if row_rel != 0 && rowx >= 8192 {
            rowx -= 16384;
        }
        if col_rel != 0 && colx >= 128 {
            colx -= 256;
        }
    } else {
        if row_rel != 0 {
            rowx -= browx.ok_or_else(none_op)?;
        }
        if col_rel != 0 {
            colx -= bcolx.ok_or_else(none_op)?;
        }
    }
    Ok((rowx, colx, row_rel, col_rel))
}

fn get_cell_addr(
    data: &[u8],
    pos: i64,
    bv: i32,
    reldelta: bool,
    browx: Option<i64>,
    bcolx: Option<i64>,
) -> R<Addr> {
    if bv >= 80 {
        let b = need(span(data, pos, 4), 4)?;
        Ok(adjust_biff8(
            i64::from(u16_at(b, 0)),
            i64::from(u16_at(b, 2)),
            reldelta,
            browx,
            bcolx,
        ))
    } else {
        let b = need(span(data, pos, 3), 3)?;
        adjust_le7(
            i64::from(u16_at(b, 0)),
            i64::from(u8_at(b, 2)),
            reldelta,
            browx,
            bcolx,
        )
    }
}

fn get_cell_range_addr(
    data: &[u8],
    pos: i64,
    bv: i32,
    reldelta: bool,
    browx: Option<i64>,
    bcolx: Option<i64>,
) -> R<(Addr, Addr)> {
    if bv >= 80 {
        let b = need(span(data, pos, 8), 8)?;
        let (r1, r2, c1, c2) = (
            i64::from(u16_at(b, 0)),
            i64::from(u16_at(b, 2)),
            i64::from(u16_at(b, 4)),
            i64::from(u16_at(b, 6)),
        );
        Ok((
            adjust_biff8(r1, c1, reldelta, browx, bcolx),
            adjust_biff8(r2, c2, reldelta, browx, bcolx),
        ))
    } else {
        let b = need(span(data, pos, 6), 6)?;
        let (r1, r2, c1, c2) = (
            i64::from(u16_at(b, 0)),
            i64::from(u16_at(b, 2)),
            i64::from(u8_at(b, 4)),
            i64::from(u8_at(b, 5)),
        );
        Ok((
            adjust_le7(r1, c1, reldelta, browx, bcolx)?,
            adjust_le7(r2, c2, reldelta, browx, bcolx)?,
        ))
    }
}

fn colname(colx: i64) -> R<String> {
    const A: &[u8; 26] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let at = |i: i64| -> R<char> {
        py_index(i128::from(i), 26)
            .and_then(|k| A.get(k))
            .map(|b| *b as char)
            .ok_or_else(|| err("IndexError", "string index out of range"))
    };
    if colx <= 25 {
        Ok(at(colx)?.to_string())
    } else {
        let (d, m) = (colx.div_euclid(26), colx.rem_euclid(26));
        let mut s = at(d - 1)?.to_string();
        s.push(at(m)?);
        Ok(s)
    }
}

fn rownamerel(rowx: i64, rowxrel: i64, browx: Option<i64>, mut r1c1: bool) -> String {
    if browx.is_none() {
        r1c1 = true;
    }
    if rowxrel == 0 {
        if r1c1 {
            return format!("R{}", rowx + 1);
        }
        return format!("${}", rowx + 1);
    }
    if r1c1 {
        if rowx != 0 {
            return format!("R[{rowx}]");
        }
        return "R".to_string();
    }
    format!("{}", (browx.unwrap_or(0) + rowx).rem_euclid(65536) + 1)
}

fn colnamerel(colx: i64, colxrel: i64, bcolx: Option<i64>, mut r1c1: bool) -> R<String> {
    if bcolx.is_none() {
        r1c1 = true;
    }
    if colxrel == 0 {
        if r1c1 {
            return Ok(format!("C{}", colx + 1));
        }
        return Ok(format!("${}", colname(colx)?));
    }
    if r1c1 {
        if colx != 0 {
            return Ok(format!("C[{colx}]"));
        }
        return Ok("C".to_string());
    }
    colname((bcolx.unwrap_or(0) + colx).rem_euclid(256))
}

fn cellnameabs(rowx: i64, colx: i64, r1c1: bool) -> R<String> {
    if r1c1 {
        return Ok(format!("R{}C{}", rowx + 1, colx + 1));
    }
    Ok(format!("${}${}", colname(colx)?, rowx + 1))
}

fn cellnamerel(
    rowx: i64,
    colx: i64,
    rowxrel: i64,
    colxrel: i64,
    browx: Option<i64>,
    bcolx: Option<i64>,
    mut r1c1: bool,
) -> R<String> {
    if rowxrel == 0 && colxrel == 0 {
        return cellnameabs(rowx, colx, r1c1);
    }
    if (rowxrel != 0 && browx.is_none()) || (colxrel != 0 && bcolx.is_none()) {
        r1c1 = true;
    }
    let c = colnamerel(colx, colxrel, bcolx, r1c1)?;
    let r = rownamerel(rowx, rowxrel, browx, r1c1);
    if r1c1 { Ok(r + &c) } else { Ok(c + &r) }
}

fn rangename2d(coords: [i64; 4]) -> R<String> {
    let [rlo, rhi, clo, chi] = coords;
    if rhi == rlo + 1 && chi == clo + 1 {
        return cellnameabs(rlo, clo, false);
    }
    let a = cellnameabs(rlo, clo, false)?;
    let b = cellnameabs(rhi - 1, chi - 1, false)?;
    Ok(format!("{a}:{b}"))
}

fn rangename2drel(
    coords: [i64; 4],
    rel: [i64; 4],
    browx: Option<i64>,
    bcolx: Option<i64>,
    mut r1c1: bool,
) -> R<String> {
    let [rlo, rhi, clo, chi] = coords;
    let [rlorel, rhirel, clorel, chirel] = rel;
    if (rlorel != 0 || rhirel != 0) && browx.is_none() {
        r1c1 = true;
    }
    if (clorel != 0 || chirel != 0) && bcolx.is_none() {
        r1c1 = true;
    }
    let start = cellnamerel(rlo, clo, rlorel, clorel, browx, bcolx, r1c1)?;
    let end = cellnamerel(rhi - 1, chi - 1, rhirel, chirel, browx, bcolx, r1c1)?;
    if start == end {
        Ok(start)
    } else {
        Ok(format!("{start}:{end}"))
    }
}

/// Unit prints of the source's `print("  ", res)`.
fn tup(v: &[i64]) -> String {
    let parts: Vec<String> = v.iter().map(i64::to_string).collect();
    format!("({})", parts.join(", "))
}

impl Loader<'_, '_> {
    fn quotedsheetname(&self, shx: i64) -> R<String> {
        let name = if shx >= 0 {
            self.sheet_names
                .get(shx as usize)
                .cloned()
                .ok_or_else(list_index_error)?
        } else {
            match shx {
                -1 => "?internal; any sheet?".to_string(),
                -2 => "internal; deleted sheet".to_string(),
                -3 => "internal; macro sheet".to_string(),
                -4 => "<<external>>".to_string(),
                _ => format!("?error {shx}?"),
            }
        };
        Ok(format!("'{name}'"))
    }

    fn sheetrange(&self, slo: i64, shi: i64) -> R<String> {
        let mut d = self.quotedsheetname(slo)?;
        if slo != shi - 1 {
            d.push(':');
            d.push_str(&self.quotedsheetname(shi - 1)?);
        }
        Ok(d)
    }

    fn rangename3d(&self, c: &[i64; 6]) -> R<String> {
        let sh = self.sheetrange(c[0], c[1])?;
        Ok(format!("{sh}!{}", rangename2d([c[2], c[3], c[4], c[5]])?))
    }

    fn rangename3drel(
        &self,
        c: &[i64; 6],
        rel: [i64; 4],
        browx: Option<i64>,
        bcolx: Option<i64>,
        r1c1: bool,
    ) -> R<String> {
        let sh = self.sheetrange(c[0], c[1])?;
        let rng = rangename2drel([c[2], c[3], c[4], c[5]], rel, browx, bcolx, r1c1)?;
        Ok(format!("{sh}!{rng}"))
    }

    fn get_externsheet_local_range(&mut self, refx: i64, blah: bool) -> R<(i64, i64)> {
        let Some(&info) = self.externsheet_info.get(refx as usize) else {
            self.log.push_str(&format!(
                "!!! get_externsheet_local_range: refx={refx}, not in range({})\n",
                self.externsheet_info.len()
            ));
            return Ok((-101, -101));
        };
        let (rec, first, last) = (i64::from(info.0), i64::from(info.1), i64::from(info.2));
        let shown = tup(&[rec, first, last]);
        if Some(rec) == self.supbook_addins_inx {
            if blah {
                self.log.push_str(&format!(
                    "/// get_externsheet_local_range(refx={refx}) -> addins {shown}\n"
                ));
            }
            if !(first == 0xFFFE && last == 0xFFFE) {
                return Err(assertion());
            }
            return Ok((-5, -5));
        }
        if Some(rec) != self.supbook_locals_inx {
            if blah {
                self.log.push_str(&format!(
                    "/// get_externsheet_local_range(refx={refx}) -> external {shown}\n"
                ));
            }
            return Ok((-4, -4));
        }
        if first == 0xFFFE && last == 0xFFFE {
            if blah {
                self.log.push_str(&format!(
                    "/// get_externsheet_local_range(refx={refx}) -> unspecified sheet {shown}\n"
                ));
            }
            return Ok((-1, -1));
        }
        if first == 0xFFFF && last == 0xFFFF {
            if blah {
                self.log.push_str(&format!(
                    "/// get_externsheet_local_range(refx={refx}) -> deleted sheet(s)\n"
                ));
            }
            return Ok((-2, -2));
        }
        let nsheets = self.all_sheets_map.len() as i64;
        if !(0 <= first && first <= last && last < nsheets) {
            if blah {
                self.log.push_str(&format!(
                    "/// get_externsheet_local_range(refx={refx}) -> {shown}\n--- first/last sheet not in range({nsheets})\n"
                ));
            }
            return Ok((-102, -102));
        }
        self.map_sheet_pair(first, last)
    }

    fn map_sheet_pair(&self, first: i64, last: i64) -> R<(i64, i64)> {
        let x1 = self
            .all_sheets_map
            .get(first as usize)
            .copied()
            .unwrap_or(-1);
        let x2 = self
            .all_sheets_map
            .get(last as usize)
            .copied()
            .unwrap_or(-1);
        if !(0 <= x1 && x1 <= x2) {
            return Ok((-3, -3));
        }
        Ok((x1, x2))
    }

    fn get_externsheet_local_range_b57(
        &mut self,
        raw_extshtx: i64,
        first: i64,
        last: i64,
        blah: bool,
    ) -> R<(i64, i64)> {
        if raw_extshtx > 0 {
            if blah {
                self.log.push_str(&format!(
                    "/// get_externsheet_local_range_b57(raw_extshtx={raw_extshtx}) -> external\n"
                ));
            }
            return Ok((-4, -4));
        }
        if first == -1 && last == -1 {
            return Ok((-2, -2));
        }
        let nsheets = self.all_sheets_map.len() as i64;
        if !(0 <= first && first <= last && last < nsheets) {
            if blah {
                self.log.push_str(&format!(
                    "/// get_externsheet_local_range_b57({raw_extshtx}, {first}, {last}) -> ???\n--- first/last sheet not in range({nsheets})\n"
                ));
            }
            return Ok((-103, -103));
        }
        self.map_sheet_pair(first, last)
    }

    /// `"%s!%s" % (bk._sheet_names[scope], name)`, or the bare name for global scope.
    fn scoped_name(&self, namex: usize) -> R<String> {
        let t = self.names.get(namex).ok_or_else(list_index_error)?;
        if t.scope == -1 {
            return Ok(t.name.clone());
        }
        let sh = py_index(i128::from(t.scope), self.sheet_names.len())
            .and_then(|i| self.sheet_names.get(i))
            .ok_or_else(list_index_error)?;
        Ok(format!("{sh}!{}", t.name))
    }

    /// `(raw_extshtx, shx1, shx2)` of a BIFF5/7 3D reference.
    fn raw_3d(data: &[u8], pos: i64) -> R<(i64, i64, i64)> {
        let b = need(slice(data, pos + 1, pos + 15), 14)?;
        Ok((
            i64::from(i16_at(b, 0)),
            i64::from(i16_at(b, 10)),
            i64::from(i16_at(b, 12)),
        ))
    }

    /// formula.dump_formula with blah=0: it only reports by raising or by these prints.
    pub(crate) fn dump_formula(
        &mut self,
        data: &[u8],
        fmlalen: i64,
        bv: i32,
        reldelta: i32,
    ) -> R<()> {
        if bv < 80 {
            return Err(assertion());
        }
        let tab = sztab(bv);
        let reldelta = reldelta != 0;
        let mut pos = 0i64;
        // Each stack item is a list; only its length ever matters.
        let mut stack: Vec<usize> = Vec::new();
        while 0 <= pos && pos < fmlalen {
            self.poll()?;
            let op = byte_at(data, pos)?;
            let opcode = op & 0x1f;
            let optype = (op & 0x60) >> 5;
            let opx = usize::from(if optype != 0 { opcode + 32 } else { opcode });
            let mut sz = token_size(tab, opx);
            if optype == 0 {
                match opcode {
                    0x01 | 0x02 => {
                        need(slice(data, pos + 1, pos + 5), 4)?;
                    }
                    0x10 => {
                        let (b, a) = pop2(&mut stack)?;
                        stack.push(a + b);
                    }
                    0x11 | 0x0F => {
                        let (b, a) = pop2(&mut stack)?;
                        if a != 1 || b != 1 {
                            return Err(assertion());
                        }
                        return Err(err(
                            "AttributeError",
                            "'tuple' object has no attribute 'coords'",
                        ));
                    }
                    0x19 => {
                        let b = need(slice(data, pos + 1, pos + 4), 3)?;
                        sz = if u8_at(b, 0) == 0x04 {
                            i64::from(u16_at(b, 1)) * 2 + 6
                        } else {
                            4
                        };
                    }
                    0x17 => {
                        let (_s, newpos) = unpack_unicode_update_pos(data, pos + 1, 1, None)?;
                        sz = newpos - pos;
                    }
                    _ => {
                        if sz <= 0 {
                            self.log.push_str("**** Dud size; exiting ****\n");
                            return Ok(());
                        }
                    }
                }
                pos += sz;
                continue;
            }
            match opcode {
                0x00 => {}
                0x01 => {
                    need(slice(data, pos + 1, pos + 3), 2)?;
                }
                0x02 => {
                    need(slice(data, pos + 1, pos + 4), 3)?;
                }
                0x03 | 0x09 => {
                    need(slice(data, pos + 1, pos + 3), 2)?;
                }
                0x04 => {
                    get_cell_addr(data, pos + 1, bv, reldelta, None, None)?;
                }
                0x05 => {
                    get_cell_range_addr(data, pos + 1, bv, reldelta, None, None)?;
                }
                0x0C => {
                    get_cell_addr(data, pos + 1, bv, true, None, None)?;
                }
                0x0D => {
                    get_cell_range_addr(data, pos + 1, bv, true, None, None)?;
                }
                0x1A => {
                    let refx = i64::from(u16_at(need(slice(data, pos + 1, pos + 3), 2)?, 0));
                    get_cell_addr(data, pos + 3, bv, reldelta, None, None)?;
                    self.get_externsheet_local_range(refx, false)?;
                    if optype == 1 {
                        stack.push(1);
                    }
                }
                0x1B => {
                    let refx = i64::from(u16_at(need(slice(data, pos + 1, pos + 3), 2)?, 0));
                    get_cell_range_addr(data, pos + 3, bv, reldelta, None, None)?;
                    self.get_externsheet_local_range(refx, false)?;
                    if optype == 1 {
                        stack.push(1);
                    }
                }
                0x19 => {
                    need(slice(data, pos + 1, pos + 5), 4)?;
                }
                _ => {}
            }
            if sz <= 0 {
                self.log.push_str("**** Dud size; exiting ****\n");
                return Ok(());
            }
            pos += sz;
        }
        Ok(())
    }

    /// formula.evaluate_name_formula. `namex` is the index as Python passes it, possibly -1.
    pub(crate) fn evaluate_name_formula(
        &mut self,
        nidx: usize,
        namex: i64,
        blah: bool,
        level: i32,
    ) -> R<()> {
        let blah = blah || level > STACK_ALARM_LEVEL;
        let (data, fmlalen, nm) = {
            let n = self.names.get(nidx).ok_or_else(list_index_error)?;
            (n.raw_formula, n.basic_formula_len, n.name.clone())
        };
        let bv = self.biff_version;
        if blah {
            self.log.push_str(&format!(
                "::: evaluate_name_formula {namex} {} {fmlalen} {bv} {} level={level}\n",
                repr_str(&nm),
                repr_bytes(data)
            ));
            hex_char_dump(self.log, data, 0, fmlalen);
        }
        if level > STACK_PANIC_LEVEL {
            return Err(xlrd_err("Excessive indirect references in NAME formula"));
        }
        let tab = sztab(bv);
        let mut pos = 0i64;
        let mut stack: Vec<Operand> = Vec::new();
        let mut any_rel = false;
        let mut any_err = 0i64;
        if fmlalen == 0 {
            stack.push(Operand::unk());
        }
        while 0 <= pos && pos < fmlalen {
            self.poll()?;
            let op = byte_at(data, pos)?;
            let opcode = op & 0x1f;
            let optype = (op & 0x60) >> 5;
            let opx = usize::from(if optype != 0 { opcode + 32 } else { opcode });
            let on = oname(opx);
            let mut sz = token_size(tab, opx);
            if blah {
                self.log.push_str(&format!(
                    "Pos:{pos} Op:0x{op:02x} Name:t{on} Sz:{sz} opcode:{opcode:02x}h optype:{optype:02x}h\nStack = {}\n",
                    stack_repr(&stack)
                ));
            }
            if sz == -2 {
                return Err(formula_error(format!(
                    "ERROR *** Unexpected token 0x{op:02x} (\"{on}\"); biff_version={bv}"
                )));
            }
            if optype == 0 {
                match opcode {
                    0x00..=0x02 => {
                        return Err(formula_error(format!(
                            "ERROR *** Token 0x{op:02x} ({on}) found in NAME formula"
                        )));
                    }
                    0x03..=0x0E => pyval::do_binop(opcode, &mut stack)?,
                    0x0F..=0x11 => self.eval_box_op(opcode, &mut stack, blah)?,
                    0x12..=0x14 => pyval::do_unaryop(opcode, &mut stack)?,
                    0x15 => {}
                    0x16 => stack.push(Operand::new(O_MSNG, LEAF_RANK, "")),
                    0x17 => {
                        let (strg, newpos) = if bv <= 70 {
                            unpack_string_update_pos(
                                data,
                                pos + 1,
                                self.encoding.as_ref(),
                                1,
                                None,
                            )?
                        } else {
                            unpack_unicode_update_pos(data, pos + 1, 1, None)?
                        };
                        sz = newpos - pos;
                        if blah {
                            self.log
                                .push_str(&format!("   sz={sz} strg={}\n", repr_str(&strg)));
                        }
                        let text = format!("\"{}\"", strg.replace('"', "\"\""));
                        stack.push(Operand::with_value(
                            O_STRG,
                            PyVal::Str(strg),
                            LEAF_RANK,
                            text,
                        ));
                    }
                    0x18 => {
                        if bv < 80 {
                            return Err(assertion());
                        }
                        return Err(formula_error("tExtended token not implemented"));
                    }
                    0x19 => {
                        let b = need(slice(data, pos + 1, pos + 4), 3)?;
                        let (subop, nc) = (u8_at(b, 0), i64::from(u16_at(b, 1)));
                        if subop == 0x04 {
                            sz = nc * 2 + 6;
                        } else if subop == 0x10 {
                            sz = 4;
                            if blah {
                                self.log
                                    .push_str(&format!("tAttrSum {}\n", stack_repr(&stack)));
                            }
                            let last = stack.last_mut().ok_or_else(assertion)?;
                            let otext = format!("SUM({})", last.attr("text")?.text);
                            *last = Operand::new(O_NUM, FUNC_RANK, otext);
                        } else {
                            sz = 4;
                        }
                        if blah {
                            let subname = attr_name(subop);
                            self.log.push_str(&format!(
                                "   subop={subop:02x}h subname=t{subname} sz={sz} nc={nc:02x}h\n"
                            ));
                        }
                    }
                    0x1A | 0x1B => {
                        if bv >= 50 {
                            return Err(assertion());
                        }
                        return Err(formula_error("tSheet & tEndsheet tokens not implemented"));
                    }
                    0x1C..=0x1F => stack.push(leaf_constant(data, pos, opcode, true)?),
                    _ => {
                        return Err(formula_error(format!("Unhandled opcode: 0x{opcode:02x}")));
                    }
                }
                if sz <= 0 {
                    return Err(formula_error(format!(
                        "Size not set for opcode 0x{opcode:02x}"
                    )));
                }
                pos += sz;
                continue;
            }
            match opcode {
                0x00 => {
                    let (items, text) = parse_array(data, pos)?;
                    stack.push(Operand::with_value(
                        O_ARR,
                        PyVal::Arr(items),
                        FUNC_RANK,
                        text,
                    ));
                }
                0x01 => {
                    let funcx = func_index_1(data, pos, bv)?;
                    match func_def(funcx) {
                        None => {
                            self.log
                                .push_str(&format!("*** formula/tFunc unknown FuncID:{funcx}\n"));
                            stack.push(Operand::unk());
                        }
                        Some((func_name, nargs, _)) => {
                            if blah {
                                self.log.push_str(&format!(
                                    "    FuncID={funcx} name={func_name} nargs={nargs}\n"
                                ));
                            }
                            let r = func_result(&mut stack, func_name, nargs)?;
                            stack.push(r);
                        }
                    }
                }
                0x02 => self.eval_funcvar(data, pos, bv, blah, &mut stack)?,
                0x03 => {
                    let tgtnamex =
                        i64::from(u16_at(need(slice(data, pos + 1, pos + 3), 2)?, 0)) - 1;
                    if blah {
                        self.log.push_str(&format!("   tgtnamex={tgtnamex}\n"));
                    }
                    let res = self.eval_target_name(
                        tgtnamex,
                        blah,
                        level,
                        &mut any_err,
                        &mut any_rel,
                        "!!! tgtobj has problems!!!",
                        "-----------       --------",
                    )?;
                    if blah {
                        self.log.push_str(&format!(
                            "    tName: setting text to {}\n",
                            repr_str(&res.text)
                        ));
                    }
                    stack.push(res);
                }
                0x04 => {
                    let (rowx, colx, row_rel, col_rel) =
                        get_cell_addr(data, pos + 1, bv, true, None, None)?;
                    if blah {
                        self.log
                            .push_str(&format!("   {}\n", tup(&[rowx, colx, row_rel, col_rel])));
                    }
                    any_rel = true;
                    let coords = [0, 1, rowx, rowx + 1, colx, colx + 1];
                    if blah {
                        self.log.push_str(&format!("    {}\n", tup(&coords)));
                    }
                    let mut res = Operand::unk();
                    if optype == 1 {
                        let rel = [1, 1, row_rel, row_rel, col_rel, col_rel];
                        res = Operand::with_value(
                            O_REL,
                            PyVal::Refs(vec![Ref3D::new(coords, Some(rel))]),
                            0,
                            "?",
                        );
                    }
                    stack.push(res);
                }
                0x05 => {
                    let (a, b) = get_cell_range_addr(data, pos + 1, bv, true, None, None)?;
                    if blah {
                        self.log.push_str(&format!(
                            "   {} {}\n",
                            tup(&[a.0, a.1, a.2, a.3]),
                            tup(&[b.0, b.1, b.2, b.3])
                        ));
                    }
                    any_rel = true;
                    let coords = [0, 1, a.0, b.0 + 1, a.1, b.1 + 1];
                    if blah {
                        self.log.push_str(&format!("    {}\n", tup(&coords)));
                    }
                    let mut res = Operand::unk();
                    if optype == 1 {
                        let rel = [1, 1, a.2, b.2, a.3, b.3];
                        res = Operand::with_value(
                            O_REL,
                            PyVal::Refs(vec![Ref3D::new(coords, Some(rel))]),
                            0,
                            "?",
                        );
                    }
                    stack.push(res);
                }
                0x06 | 0x0C | 0x0D => {
                    return Err(formula_error(format!(
                        "ERROR *** Token 0x{op:02x} ({on}) found in NAME formula"
                    )));
                }
                0x09 => {
                    let nb = u16_at(need(slice(data, pos + 1, pos + 3), 2)?, 0);
                    if blah {
                        self.log
                            .push_str(&format!("  {nb} bytes of cell ref formula\n"));
                    }
                }
                0x1A => {
                    let res = if bv >= 80 {
                        let r = get_cell_addr(data, pos + 3, bv, true, None, None)?;
                        let refx = i64::from(u16_at(need(slice(data, pos + 1, pos + 3), 2)?, 0));
                        (r, self.get_externsheet_local_range(refx, blah)?)
                    } else {
                        let r = get_cell_addr(data, pos + 15, bv, true, None, None)?;
                        let (raw, s1, s2) = Self::raw_3d(data, pos)?;
                        if blah {
                            self.log.push_str(&format!("tRef3d {raw} {s1} {s2}\n"));
                        }
                        (r, self.get_externsheet_local_range_b57(raw, s1, s2, blah)?)
                    };
                    let ((rowx, colx, row_rel, col_rel), (shx1, shx2)) = res;
                    let is_rel = row_rel != 0 || col_rel != 0;
                    any_rel = any_rel || is_rel;
                    let coords = [shx1, shx2 + 1, rowx, rowx + 1, colx, colx + 1];
                    any_err |= i64::from(shx1 < -1);
                    if blah {
                        self.log.push_str(&format!("    {}\n", tup(&coords)));
                    }
                    let rel = [0, 0, row_rel, row_rel, col_rel, col_rel];
                    stack.push(self.eval_3d(coords, rel, is_rel, optype)?);
                }
                0x1B => {
                    let res = if bv >= 80 {
                        let r = get_cell_range_addr(data, pos + 3, bv, true, None, None)?;
                        let refx = i64::from(u16_at(need(slice(data, pos + 1, pos + 3), 2)?, 0));
                        (r, self.get_externsheet_local_range(refx, blah)?)
                    } else {
                        let r = get_cell_range_addr(data, pos + 15, bv, true, None, None)?;
                        let (raw, s1, s2) = Self::raw_3d(data, pos)?;
                        if blah {
                            self.log.push_str(&format!("tArea3d {raw} {s1} {s2}\n"));
                        }
                        (r, self.get_externsheet_local_range_b57(raw, s1, s2, blah)?)
                    };
                    let ((a, b), (shx1, shx2)) = res;
                    any_err |= i64::from(shx1 < -1);
                    let is_rel = a.2 != 0 || a.3 != 0 || b.2 != 0 || b.3 != 0;
                    any_rel = any_rel || is_rel;
                    let coords = [shx1, shx2 + 1, a.0, b.0 + 1, a.1, b.1 + 1];
                    if blah {
                        self.log.push_str(&format!("    {}\n", tup(&coords)));
                    }
                    let rel = [0, 0, a.2, b.2, a.3, b.3];
                    stack.push(self.eval_3d(coords, rel, is_rel, optype)?);
                }
                0x19 => {
                    let mut dodgy = false;
                    let (mut refx, tgtnamex, origrefx);
                    if bv >= 80 {
                        let b = need(slice(data, pos + 1, pos + 5), 4)?;
                        refx = i64::from(u16_at(b, 0));
                        tgtnamex = i64::from(u16_at(b, 2)) - 1;
                        origrefx = refx;
                    } else {
                        let b = need(slice(data, pos + 1, pos + 13), 12)?;
                        refx = i64::from(i16_at(b, 0));
                        tgtnamex = i64::from(u16_at(b, 10)) - 1;
                        origrefx = refx;
                        if refx > 0 {
                            refx -= 1;
                        } else if refx < 0 {
                            refx = -refx - 1;
                        } else {
                            dodgy = true;
                        }
                    }
                    if blah {
                        self.log.push_str(&format!(
                            "   origrefx={origrefx} refx={refx} tgtnamex={tgtnamex} dodgy={}\n",
                            i32::from(dodgy)
                        ));
                    }
                    if tgtnamex == namex {
                        if blah {
                            self.log.push_str("!!!! Self-referential !!!!\n");
                        }
                        dodgy = true;
                        any_err = 1;
                    }
                    let mut shx1 = 0;
                    if !dodgy {
                        shx1 = if bv >= 80 {
                            self.get_externsheet_local_range(refx, blah)?.0
                        } else if origrefx > 0 {
                            -4
                        } else {
                            let exty = self
                                .externsheet_type_b57
                                .get(refx as usize)
                                .copied()
                                .ok_or_else(list_index_error)?;
                            if exty == 4 { -1 } else { -666 }
                        };
                    }
                    let res = if dodgy || shx1 < -1 {
                        Operand::new(
                            O_UNK,
                            LEAF_RANK,
                            format!("<<Name #{tgtnamex} in external(?) file #{origrefx}>>"),
                        )
                    } else {
                        let r = self.eval_target_name(
                            tgtnamex,
                            blah,
                            level,
                            &mut any_err,
                            &mut any_rel,
                            "!!! bad tgtobj !!!",
                            "------------------",
                        )?;
                        if blah {
                            self.log.push_str(&format!(
                                "    tNameX: setting text to {}\n",
                                repr_str(&r.text)
                            ));
                        }
                        r
                    };
                    stack.push(res);
                }
                _ if is_error_opcode(opcode) => {
                    any_err = 1;
                    stack.push(Operand::err_opnd());
                }
                _ => {
                    if blah {
                        self.log
                            .push_str(&format!("FORMULA: /// Not handled yet: t{on}\n"));
                    }
                    any_err = 1;
                }
            }
            if sz <= 0 {
                return Err(formula_error("Fatal: token size is not positive"));
            }
            pos += sz;
        }
        if blah {
            self.log.push_str(&format!(
                "End of formula. level={level} any_rel={} any_err={any_err} stack={}\n",
                i32::from(any_rel),
                crate::py::ascii_str_repr(&stack_repr(&stack))
            ));
            if stack.len() >= 2 {
                self.log.push_str("*** Stack has unprocessed args\n");
            }
            self.log.push('\n');
        }
        let n = self.names.get_mut(nidx).ok_or_else(list_index_error)?;
        n.stack = stack;
        n.any_rel = any_rel;
        n.any_err = any_err;
        n.evaluated = true;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_target_name(
        &mut self,
        tgtnamex: i64,
        blah: bool,
        level: i32,
        any_err: &mut i64,
        any_rel: &mut bool,
        header: &str,
        footer: &str,
    ) -> R<Operand> {
        let tidx = py_index(i128::from(tgtnamex), self.names.len()).ok_or_else(list_index_error)?;
        if !self.names.get(tidx).is_some_and(|t| t.evaluated) {
            self.evaluate_name_formula(tidx, tgtnamex, blah, level + 1)?;
        }
        let t = self.names.get(tidx).ok_or_else(list_index_error)?;
        let mut res;
        if t.macro_ != 0 || t.binary != 0 || t.any_err != 0 {
            if blah {
                t.dump(self.log, header, footer);
            }
            let t = self.names.get(tidx).ok_or_else(list_index_error)?;
            res = Operand::unk();
            if *any_err == 0 {
                *any_err = if t.macro_ != 0 {
                    i64::from(t.macro_)
                } else if t.binary != 0 {
                    i64::from(t.binary)
                } else {
                    t.any_err
                };
            }
            *any_rel = *any_rel || t.any_rel;
        } else {
            if t.stack.len() != 1 {
                return Err(assertion());
            }
            res = t.stack.first().cloned().ok_or_else(assertion)?;
        }
        if res.bare {
            return Err(err(
                "AttributeError",
                "'int' object has no attribute 'rank' and no __dict__ for setting new attributes",
            ));
        }
        res.rank = LEAF_RANK;
        res.text = self.scoped_name(tidx)?;
        Ok(res)
    }

    fn eval_3d(&self, coords: [i64; 6], rel: [i64; 6], is_rel: bool, optype: u8) -> R<Operand> {
        let mut res = Operand::unk();
        let rel4 = [rel[2], rel[3], rel[4], rel[5]];
        let r = if is_rel {
            res.kind = O_REL;
            res.text = self.rangename3drel(&coords, rel4, None, None, true)?;
            Ref3D::new(coords, Some(rel))
        } else {
            res.kind = O_REF;
            res.text = self.rangename3d(&coords)?;
            Ref3D::new(coords, None)
        };
        res.rank = LEAF_RANK;
        if optype == 1 {
            res.value = Some(PyVal::Refs(vec![r]));
        }
        Ok(res)
    }

    fn eval_box_op(&mut self, opcode: u8, stack: &mut Vec<Operand>, blah: bool) -> R<()> {
        let tag = match opcode {
            0x0F => "tIsect",
            0x10 => "tList",
            _ => "tRange",
        };
        if blah {
            self.log
                .push_str(&format!("{tag} pre {}\n", stack_repr(stack)));
        }
        let (bop, aop) = pop2(stack)?;
        let otext = joined_text(&aop, &bop, 80, opcode)?;
        let res = pyval::box_op(opcode, &aop, &bop, otext)?;
        stack.push(res);
        if blah {
            self.log
                .push_str(&format!("{tag} post {}\n", stack_repr(stack)));
        }
        Ok(())
    }

    fn eval_funcvar(
        &mut self,
        data: &[u8],
        pos: i64,
        bv: i32,
        blah: bool,
        stack: &mut Vec<Operand>,
    ) -> R<()> {
        let (nargs, funcx_val) = func_var_args(data, pos, bv)?;
        let prompt = nargs.div_euclid(128);
        let nargs = nargs.rem_euclid(128);
        let macro_ = funcx_val.div_euclid(32768);
        let funcx = funcx_val.rem_euclid(32768);
        if blah {
            self.log.push_str(&format!(
                "   FuncID={funcx} nargs={nargs} macro={macro_} prompt={prompt}\n"
            ));
        }
        let Some((func_name, minargs, maxargs)) = func_def(funcx) else {
            self.log
                .push_str(&format!("*** formula/tFuncVar unknown FuncID:{funcx}\n"));
            stack.push(Operand::unk());
            return Ok(());
        };
        if blah {
            self.log.push_str(&format!(
                "    name: {}, min~max args: {minargs}~{maxargs}\n",
                repr_str(func_name)
            ));
        }
        if !(minargs <= nargs && nargs <= maxargs) || (stack.len() as i64) < nargs {
            return Err(assertion());
        }
        // stack[-0:] is the whole stack, and del stack[-0:] clears it.
        let start = if nargs == 0 {
            0
        } else {
            stack.len() - nargs as usize
        };
        let argtext = join_args(stack.get(start..).unwrap_or(&[]))?;
        let mut res = Operand::new(O_UNK, FUNC_RANK, format!("{func_name}({argtext})"));
        if funcx == 1 {
            let testarg = stack
                .get(start)
                .ok_or_else(list_index_error)?
                .attr("kind")?;
            if testarg.kind != O_NUM && testarg.kind != O_BOOL {
                if blah && testarg.kind != O_UNK {
                    self.log.push_str("IF testarg kind?\n");
                }
            } else if !pyval::in_zero_one(testarg.value.as_ref()) {
                if blah && testarg.value.is_some() {
                    self.log.push_str("IF testarg value?\n");
                }
            } else {
                let tv = testarg.value.as_ref().ok_or_else(assertion)?;
                if nargs == 2 && !pyval::truthy(tv) {
                    res.kind = O_BOOL;
                    res.value = Some(PyVal::Int(0));
                } else {
                    let respos = -nargs + 2 - pyval::to_int(tv)?;
                    let chosen = py_index(i128::from(respos), stack.len())
                        .and_then(|i| stack.get(i))
                        .ok_or_else(list_index_error)?
                        .attr("kind")?;
                    pyval::take_choice(&mut res, chosen);
                }
                if blah {
                    self.log.push_str("$$$$$$ IF => constant\n");
                }
            }
        } else if funcx == 100 {
            let testarg = stack
                .get(start)
                .ok_or_else(list_index_error)?
                .attr("kind")?;
            if testarg.kind == O_NUM && pyval::choose_in_range(testarg.value.as_ref(), nargs)? {
                let tv = testarg.value.as_ref().ok_or_else(assertion)?;
                let at = -nargs + pyval::to_int(tv)?;
                let chosen = py_index(i128::from(at), stack.len())
                    .and_then(|i| stack.get(i))
                    .ok_or_else(list_index_error)?
                    .attr("kind")?;
                pyval::take_choice(&mut res, chosen);
            }
        }
        stack.truncate(start);
        stack.push(res);
        Ok(())
    }

    /// formula.decompile_formula. blah is always 0 and level 0 here: nothing recurses.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn decompile_formula(
        &mut self,
        fmla: &[u8],
        fmlalen: i64,
        fmlatype: u8,
        browx: i64,
        bcolx: i64,
        sheet_id: i64,
    ) -> R<Option<String>> {
        let reldelta = fmlatype != FMLA_TYPE_CELL;
        let data = fmla;
        let bv = self.biff_version;
        let tab = sztab(bv);
        let (b_row, b_col) = (Some(browx), Some(bcolx));
        let mut pos = 0i64;
        let mut stack: Vec<Operand> = Vec::new();
        let mut shx1_var: Option<i64> = None;
        if fmlalen == 0 {
            stack.push(Operand::unk());
        }
        while 0 <= pos && pos < fmlalen {
            self.poll()?;
            let op = byte_at(data, pos)?;
            let opcode = op & 0x1f;
            let optype = (op & 0x60) >> 5;
            let opx = usize::from(if optype != 0 { opcode + 32 } else { opcode });
            let on = oname(opx);
            let mut sz = token_size(tab, opx);
            if sz == -2 {
                return Err(formula_error(format!(
                    "ERROR *** Unexpected token 0x{op:02x} (\"{on}\"); biff_version={bv}"
                )));
            }
            if token_not_allowed(opx) & fmlatype != 0 {
                self.unexpected_opcode(op, on, fmlatype);
            }
            if optype == 0 {
                match opcode {
                    0x00 | 0x01 => {
                        let size = if bv >= 30 { 5 } else { 4 };
                        if !(pos == 0 && fmlalen == sz && stack.is_empty()) {
                            return Err(assertion());
                        }
                        let b = need(data, size)?;
                        let rowx = u16_at(b, 1);
                        let colx = if bv >= 30 {
                            i64::from(u16_at(b, 3))
                        } else {
                            i64::from(u8_at(b, 3))
                        };
                        stack.push(Operand::new(
                            O_UNK,
                            LEAF_RANK,
                            format!("SHARED FMLA at rowx={rowx} colx={colx}"),
                        ));
                        if fmlatype & (FMLA_TYPE_CELL | 4) == 0 {
                            self.unexpected_opcode(op, on, fmlatype);
                        }
                    }
                    0x03..=0x0E => {
                        let (bop, aop) = pop2(&mut stack)?;
                        let otext = binop_text(&aop, &bop, opcode)?;
                        let (kind, rank) = pyval::binop_kind_rank(opcode);
                        stack.push(Operand::new(kind, rank, otext));
                    }
                    0x0F => {
                        let (bop, aop) = pop2(&mut stack)?;
                        let otext = joined_text(&aop, &bop, 80, opcode)?;
                        let mut res = Operand::new(O_REF, 0, otext);
                        if bop.attr("kind")?.kind == O_ERR || aop.attr("kind")?.kind == O_ERR {
                            res.kind = O_ERR;
                        } else if bop.kind == O_UNK || aop.kind == O_UNK {
                        } else if bop.kind == O_REL && aop.kind == O_REL {
                            res.kind = O_REL;
                        }
                        stack.push(res);
                    }
                    0x10 => {
                        let (bop, aop) = pop2(&mut stack)?;
                        let otext = joined_text(&aop, &bop, 80, opcode)?;
                        let mut res = Operand::new(O_REF, 80, otext);
                        let is_ref = |k: i8| k == O_REF || k == O_REL;
                        if bop.attr("kind")?.kind == O_ERR || aop.attr("kind")?.kind == O_ERR {
                            res.kind = O_ERR;
                        } else if is_ref(bop.kind) && is_ref(aop.kind) {
                            res.kind = O_REF;
                            if aop.kind == O_REL || bop.kind == O_REL {
                                res.kind = O_REL;
                            }
                        }
                        stack.push(res);
                    }
                    0x11 => {
                        let (bop, aop) = pop2(&mut stack)?;
                        let otext = joined_text(&aop, &bop, 80, opcode)?;
                        let res =
                            if bop.attr("kind")?.kind == O_ERR || aop.attr("kind")?.kind == O_ERR {
                                Operand::bare_err()
                            } else {
                                Operand::new(O_REF, 80, otext)
                            };
                        stack.push(res);
                    }
                    0x12..=0x14 => {
                        let aop = stack.pop().ok_or_else(assertion)?;
                        let (rank, sym1, sym2) = pyval::unop_parts(opcode);
                        let lp = aop.attr("rank")?.rank < rank;
                        let otext = format!(
                            "{sym1}{}{}{}{sym2}",
                            if lp { "(" } else { "" },
                            aop.text,
                            if lp { ")" } else { "" },
                        );
                        stack.push(Operand::new(O_NUM, rank, otext));
                    }
                    0x15 => {}
                    0x16 => stack.push(Operand::new(O_MSNG, LEAF_RANK, "")),
                    0x17 => {
                        let (strg, newpos) = if bv <= 70 {
                            unpack_string_update_pos(
                                data,
                                pos + 1,
                                self.encoding.as_ref(),
                                1,
                                None,
                            )?
                        } else {
                            unpack_unicode_update_pos(data, pos + 1, 1, None)?
                        };
                        sz = newpos - pos;
                        let text = format!("\"{}\"", strg.replace('"', "\"\""));
                        stack.push(Operand::new(O_STRG, LEAF_RANK, text));
                    }
                    0x18 => {
                        if bv < 80 {
                            return Err(assertion());
                        }
                        return Err(formula_error("tExtended token not implemented"));
                    }
                    0x19 => {
                        let b = need(slice(data, pos + 1, pos + 4), 3)?;
                        let (subop, nc) = (u8_at(b, 0), i64::from(u16_at(b, 1)));
                        if subop == 0x04 {
                            sz = nc * 2 + 6;
                        } else if subop == 0x10 {
                            sz = 4;
                            let last = stack.last_mut().ok_or_else(assertion)?;
                            let otext = format!("SUM({})", last.attr("text")?.text);
                            *last = Operand::new(O_NUM, FUNC_RANK, otext);
                        } else {
                            sz = 4;
                        }
                    }
                    0x1A | 0x1B => {
                        if bv >= 50 {
                            return Err(assertion());
                        }
                        return Err(formula_error("tSheet & tEndsheet tokens not implemented"));
                    }
                    0x1C..=0x1F => stack.push(leaf_constant(data, pos, opcode, false)?),
                    _ => {
                        return Err(formula_error(format!("Unhandled opcode: 0x{opcode:02x}")));
                    }
                }
                if sz <= 0 {
                    return Err(formula_error(format!(
                        "Size not set for opcode 0x{opcode:02x}"
                    )));
                }
                pos += sz;
                continue;
            }
            match opcode {
                0x00 => stack.push(Operand::unk()),
                0x01 => {
                    let funcx = func_index_1(data, pos, bv)?;
                    match func_def(funcx) {
                        None => {
                            self.log
                                .push_str(&format!("*** formula/tFunc unknown FuncID:{funcx}\n"));
                            stack.push(Operand::unk());
                        }
                        Some((func_name, nargs, _)) => {
                            let r = func_result(&mut stack, func_name, nargs)?;
                            stack.push(r);
                        }
                    }
                }
                0x02 => self.decompile_funcvar(data, pos, bv, &mut stack)?,
                0x03 => {
                    let tgtnamex =
                        i64::from(u16_at(need(slice(data, pos + 1, pos + 3), 2)?, 0)) - 1;
                    let tidx = py_index(i128::from(tgtnamex), self.names.len())
                        .ok_or_else(list_index_error)?;
                    let otext = self.scoped_name(tidx)?;
                    stack.push(Operand::new(O_UNK, LEAF_RANK, otext));
                }
                0x04 | 0x0C => {
                    let (rowx, colx, row_rel, col_rel) =
                        get_cell_addr(data, pos + 1, bv, reldelta, b_row, b_col)?;
                    let okind = if row_rel != 0 || col_rel != 0 {
                        O_REL
                    } else {
                        O_REF
                    };
                    let otext = cellnamerel(rowx, colx, row_rel, col_rel, b_row, b_col, false)?;
                    stack.push(Operand::new(okind, LEAF_RANK, otext));
                }
                0x05 | 0x0D => {
                    let (a, b) = get_cell_range_addr(data, pos + 1, bv, reldelta, b_row, b_col)?;
                    let coords = [a.0, b.0 + 1, a.1, b.1 + 1];
                    let rel = [a.2, b.2, a.3, b.3];
                    let okind = if rel.iter().sum::<i64>() != 0 {
                        O_REL
                    } else {
                        O_REF
                    };
                    let otext = rangename2drel(coords, rel, b_row, b_col, false)?;
                    stack.push(Operand::new(okind, LEAF_RANK, otext));
                }
                0x06 => {}
                0x09 => {
                    need(slice(data, pos + 1, pos + 3), 2)?;
                }
                0x1A => {
                    let res = if bv >= 80 {
                        let r = get_cell_addr(data, pos + 3, bv, reldelta, b_row, b_col)?;
                        let refx = i64::from(u16_at(need(slice(data, pos + 1, pos + 3), 2)?, 0));
                        (r, self.get_externsheet_local_range(refx, false)?)
                    } else {
                        let r = get_cell_addr(data, pos + 15, bv, reldelta, b_row, b_col)?;
                        let (raw, s1, s2) = Self::raw_3d(data, pos)?;
                        (r, self.get_externsheet_local_range_b57(raw, s1, s2, false)?)
                    };
                    let ((rowx, colx, row_rel, col_rel), (shx1, shx2)) = res;
                    shx1_var = Some(shx1);
                    let coords = [shx1, shx2 + 1, rowx, rowx + 1, colx, colx + 1];
                    let mut r = Operand::unk();
                    if row_rel != 0 || col_rel != 0 {
                        r.kind = O_REL;
                        r.text = self.rangename3drel(
                            &coords,
                            [row_rel, row_rel, col_rel, col_rel],
                            b_row,
                            b_col,
                            false,
                        )?;
                    } else {
                        r.kind = O_REF;
                        r.text = self.rangename3d(&coords)?;
                    }
                    r.rank = LEAF_RANK;
                    stack.push(r);
                }
                0x1B => {
                    let res = if bv >= 80 {
                        let r = get_cell_range_addr(data, pos + 3, bv, reldelta, None, None)?;
                        let refx = i64::from(u16_at(need(slice(data, pos + 1, pos + 3), 2)?, 0));
                        (r, self.get_externsheet_local_range(refx, false)?)
                    } else {
                        let r = get_cell_range_addr(data, pos + 15, bv, reldelta, None, None)?;
                        let (raw, s1, s2) = Self::raw_3d(data, pos)?;
                        (r, self.get_externsheet_local_range_b57(raw, s1, s2, false)?)
                    };
                    let ((a, b), (shx1, shx2)) = res;
                    shx1_var = Some(shx1);
                    let is_rel = a.2 != 0 || a.3 != 0 || b.2 != 0 || b.3 != 0;
                    let coords = [shx1, shx2 + 1, a.0, b.0 + 1, a.1, b.1 + 1];
                    let mut r = Operand::unk();
                    if is_rel && sheet_id == coords[0] {
                        r.kind = O_REL;
                        r.text = self.rangename3drel(
                            &coords,
                            [a.2, b.2, a.3, b.3],
                            b_row,
                            b_col,
                            false,
                        )?;
                    } else {
                        r.kind = O_REF;
                        r.text = self.rangename3d(&coords)?;
                    }
                    r.rank = LEAF_RANK;
                    stack.push(r);
                }
                0x19 => {
                    let mut dodgy = false;
                    let (mut refx, tgtnamex, origrefx);
                    if bv >= 80 {
                        let b = need(slice(data, pos + 1, pos + 5), 4)?;
                        refx = i64::from(u16_at(b, 0));
                        tgtnamex = i64::from(u16_at(b, 2)) - 1;
                        origrefx = refx;
                    } else {
                        let b = need(slice(data, pos + 1, pos + 13), 12)?;
                        refx = i64::from(i16_at(b, 0));
                        tgtnamex = i64::from(u16_at(b, 10)) - 1;
                        origrefx = refx;
                        if refx > 0 {
                            refx -= 1;
                        } else if refx < 0 {
                            refx = -refx - 1;
                        } else {
                            dodgy = true;
                        }
                    }
                    if !dodgy {
                        let s = if bv >= 80 {
                            self.get_externsheet_local_range(refx, false)?.0
                        } else if origrefx > 0 {
                            -4
                        } else {
                            let exty = self
                                .externsheet_type_b57
                                .get(refx as usize)
                                .copied()
                                .ok_or_else(list_index_error)?;
                            if exty == 4 { -1 } else { -666 }
                        };
                        shx1_var = Some(s);
                    }
                    let shx1 = shx1_var.ok_or_else(|| crate::py::unbound("shx1"))?;
                    let res = if shx1 == -5 {
                        let v = py_index(i128::from(tgtnamex), self.addin_func_names.len())
                            .and_then(|i| self.addin_func_names.get(i))
                            .ok_or_else(list_index_error)?;
                        Operand::new(O_STRG, LEAF_RANK, format!("\"{}\"", v.replace('"', "\"\"")))
                    } else if dodgy || shx1 < -1 {
                        Operand::new(
                            O_UNK,
                            LEAF_RANK,
                            format!("<<Name #{tgtnamex} in external(?) file #{origrefx}>>"),
                        )
                    } else {
                        let tidx = py_index(i128::from(tgtnamex), self.names.len())
                            .ok_or_else(list_index_error)?;
                        Operand::new(O_UNK, LEAF_RANK, self.scoped_name(tidx)?)
                    };
                    stack.push(res);
                }
                _ if is_error_opcode(opcode) => stack.push(Operand::err_opnd()),
                _ => {}
            }
            if sz <= 0 {
                return Err(formula_error("Fatal: token size is not positive"));
            }
            pos += sz;
        }
        if stack.len() != 1 {
            return Ok(None);
        }
        let only = stack.pop().ok_or_else(assertion)?;
        only.attr("text")?;
        self.limits.spend_text(only.text.len())?;
        Ok(Some(only.text))
    }

    fn unexpected_opcode(&mut self, op: u8, on: &str, fmlatype: u8) {
        let descr = if fmlatype == FMLA_TYPE_CELL {
            "CELL"
        } else {
            "SHARED"
        };
        self.log.push_str(&format!(
            "ERROR *** Unexpected token 0x{op:02x} ({on}) found in formula type {descr}\n"
        ));
    }

    fn decompile_funcvar(
        &mut self,
        data: &[u8],
        pos: i64,
        bv: i32,
        stack: &mut Vec<Operand>,
    ) -> R<()> {
        let (nargs, funcx_val) = func_var_args(data, pos, bv)?;
        let mut nargs = nargs.rem_euclid(128);
        let funcx = funcx_val.rem_euclid(32768);
        let func_attrs: Option<(String, i64, i64)>;
        if funcx == 255 {
            if !stack.is_empty() {
                nargs -= 1;
                let first = stack.first().ok_or_else(list_index_error)?;
                first.attr("text")?;
                let idx = stack.len() as i64 - nargs - 1;
                let at = py_index(i128::from(idx), stack.len()).ok_or_else(list_index_error)?;
                let t = stack.get(at).ok_or_else(list_index_error)?.attr("text")?;
                func_attrs = Some((t.text.clone(), nargs, nargs));
                stack.remove(at);
            } else {
                func_attrs = Some(("CALL_ADDIN".to_string(), 1, 30));
            }
        } else {
            func_attrs = func_def(funcx_val).map(|(n, a, b)| (n.to_string(), a, b));
        }
        let Some((func_name, minargs, maxargs)) = func_attrs else {
            self.log
                .push_str(&format!("*** formula/tFuncVar unknown FuncID:{funcx}\n"));
            stack.push(Operand::unk());
            return Ok(());
        };
        if !(minargs <= nargs && nargs <= maxargs) || (stack.len() as i64) < nargs {
            return Err(assertion());
        }
        let mut argtext = String::new();
        if nargs > 0 {
            let start = stack.len() - nargs as usize;
            argtext = join_args(stack.get(start..).unwrap_or(&[]))?;
            stack.truncate(start);
        }
        stack.push(Operand::new(
            O_UNK,
            FUNC_RANK,
            format!("{func_name}({argtext})"),
        ));
        Ok(())
    }
}

fn attr_name(subop: u8) -> &'static str {
    match subop {
        0x00 => "Skip??",
        0x01 => "Volatile",
        0x02 => "If",
        0x04 => "Choose",
        0x08 => "Skip",
        0x10 => "Sum",
        0x20 => "Assign",
        0x40 => "Space",
        0x41 => "SpaceVolatile",
        _ => "??Unknown??",
    }
}

/// Pops (bop, aop) under the source's `assert len(stack) >= 2`.
fn pop2<T>(stack: &mut Vec<T>) -> R<(T, T)> {
    if stack.len() < 2 {
        return Err(assertion());
    }
    let b = stack.pop().ok_or_else(assertion)?;
    let a = stack.pop().ok_or_else(assertion)?;
    Ok((b, a))
}

fn paren_join(a: &Operand, b: &Operand, a_paren: bool, b_paren: bool, sym: &str) -> String {
    let mut s = String::with_capacity(a.text.len() + b.text.len() + sym.len() + 4);
    if a_paren {
        s.push('(');
    }
    s.push_str(&a.text);
    if a_paren {
        s.push(')');
    }
    s.push_str(sym);
    if b_paren {
        s.push('(');
    }
    s.push_str(&b.text);
    if b_paren {
        s.push(')');
    }
    s
}

/// tIsect, tList and tRange text: strict `<` on rank.
fn joined_text(a: &Operand, b: &Operand, rank: i32, opcode: u8) -> R<String> {
    let sym = match opcode {
        0x0F => " ",
        0x10 => ",",
        _ => ":",
    };
    let ap = a.attr("rank")?.rank < rank;
    let bp = b.attr("rank")?.rank < rank;
    Ok(paren_join(a, b, ap, bp, sym))
}

/// decompile_formula's do_binop text: `<=` on rank where the name evaluator has `<`.
fn binop_text(a: &Operand, b: &Operand, opcode: u8) -> R<String> {
    let (_, rank) = pyval::binop_kind_rank(opcode);
    let ap = a.attr("rank")?.rank <= rank;
    let bp = b.attr("rank")?.rank <= rank;
    Ok(paren_join(a, b, ap, bp, pyval::binop_sym(opcode)))
}

fn join_args(args: &[Operand]) -> R<String> {
    let mut s = String::new();
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&a.attr("text")?.text);
    }
    Ok(s)
}

fn func_index_1(data: &[u8], pos: i64, bv: i32) -> R<i64> {
    if bv >= 40 {
        Ok(i64::from(u16_at(
            need(slice(data, pos + 1, pos + 3), 2)?,
            0,
        )))
    } else {
        Ok(i64::from(u8_at(need(slice(data, pos + 1, pos + 2), 1)?, 0)))
    }
}

fn func_var_args(data: &[u8], pos: i64, bv: i32) -> R<(i64, i64)> {
    if bv >= 40 {
        let b = need(slice(data, pos + 1, pos + 4), 3)?;
        Ok((i64::from(u8_at(b, 0)), i64::from(u16_at(b, 1))))
    } else {
        let b = need(slice(data, pos + 1, pos + 3), 2)?;
        Ok((i64::from(u8_at(b, 0)), i64::from(u8_at(b, 1))))
    }
}

/// tFunc's result: `nargs` here is the function's min args.
fn func_result(stack: &mut Vec<Operand>, func_name: &str, nargs: i64) -> R<Operand> {
    if (stack.len() as i64) < nargs {
        return Err(assertion());
    }
    let otext = if nargs != 0 {
        let start = stack.len() - nargs as usize;
        let argtext = join_args(stack.get(start..).unwrap_or(&[]))?;
        stack.truncate(start);
        format!("{func_name}({argtext})")
    } else {
        format!("{func_name}()")
    };
    Ok(Operand::new(O_UNK, FUNC_RANK, otext))
}

/// tErr, tBool, tInt, tNum.
fn leaf_constant(data: &[u8], pos: i64, opcode: u8, keep_value: bool) -> R<Operand> {
    let inx = opcode - 0x1C;
    let nb = [1i64, 1, 2, 8].get(inx as usize).copied().unwrap_or(1);
    let b = need(span(data, pos + 1, nb), nb as usize)?;
    let (kind, value, text) = match inx {
        0 => {
            let v = u8_at(b, 0);
            let t = error_text(v).ok_or_else(|| err("KeyError", v.to_string()))?;
            (O_ERR, PyVal::Int(i64::from(v)), format!("\"{t}\""))
        }
        1 => {
            let v = u8_at(b, 0);
            let t = match v {
                0 => "FALSE",
                1 => "TRUE",
                _ => return Err(err("IndexError", "tuple index out of range")),
            };
            (O_BOOL, PyVal::Int(i64::from(v)), t.to_string())
        }
        2 => {
            let v = f64::from(u16_at(b, 0));
            (O_NUM, PyVal::Float(v), float_repr(v))
        }
        _ => {
            let v = f64_at(b, 0);
            (O_NUM, PyVal::Float(v), float_repr(v))
        }
    };
    if keep_value {
        Ok(Operand::with_value(kind, value, LEAF_RANK, text))
    } else {
        Ok(Operand::new(kind, LEAF_RANK, text))
    }
}

/// evaluate_name_formula's tArray: reads what follows the token, whatever fmlalen says.
fn parse_array(data: &[u8], pos: i64) -> R<(Vec<ArrItem>, String)> {
    let mut array = Vec::new();
    let mut index = pos + 11;
    loop {
        let rec_type = u8_at(need(span(data, index, 1), 1)?, 0);
        index += 1;
        if rec_type == 1 {
            let v = f64_at(need(span(data, index, 8), 8)?, 0);
            array.push(ArrItem::Num(v));
            index += 8;
        } else if rec_type == 2 {
            let b = need(span(data, index, 3), 3)?;
            let size = i64::from(u16_at(b, 0));
            index += 3;
            array.push(ArrItem::Text(crate::py::ascii(span(data, index, size))?));
            index += size;
        } else {
            break;
        }
        if index >= data.len() as i64 {
            break;
        }
    }
    let text = pyval::arr_repr(&array);
    Ok((array, text))
}
