//! pyxlsb2's tokenreader.py, formula.py and ptgs.py. Stringify is Python's recursion over a token list,
//! run here on an explicit frame stack: `frames` holds what each active Python call is waiting for, and
//! Python's recursion limit is checked against it so a deep formula raises RecursionError as it does there.

use std::collections::VecDeque;

use crate::pyfmt::{
    CONCAT_NONE, LIST_ASSIGN_RANGE, LIST_RANGE, NONE_AND, NONE_INT, NONE_PLUS_STR, fmt_opt,
    index_error, memory_error, none_attr, py_strip, type_error,
};
use crate::reader::DataReader;
use crate::{Workbook, XlError, funcs};

const RECURSION_LIMIT: usize = 1000;
/// Tokens in one formula. Python's list of objects would be several GiB at this size.
const MAX_TOKENS: usize = 16_000_000;
/// Length of any one string built while stringifying.
pub(crate) const MAX_TEXT: usize = 1 << 30;

type Val = Option<String>;

/// Cell coordinates as read; `*_abs` is the source's `*_rel`, which is true for an absolute reference.
#[derive(Clone, Copy)]
pub(crate) struct Corner {
    row: u32,
    col: u16,
    row_abs: bool,
    col_abs: bool,
}

pub(crate) enum Token {
    Binary(&'static str),
    Prefix(&'static str),
    Percent,
    Paren,
    Missing,
    Text(Val),
    Error(Option<u8>),
    Bool(Option<bool>),
    Int(Option<u16>),
    Num(Option<f64>),
    /// BasePtg.stringify with the number it prints.
    Base(u8),
    Unknown(u8),
    Literal(&'static str),
    Name(Option<u16>),
    Ref(Corner),
    Area(Corner, Corner),
    Ref3d {
        extern_idx: u16,
        row: i64,
        col: i64,
        row_abs: bool,
        col_abs: bool,
    },
    Area3d(u16, Corner, Corner),
    Attr {
        flags: Option<u8>,
        data: Option<u16>,
    },
    Func(Option<u16>),
    FuncVar {
        idx: u16,
        argc: i64,
    },
}

/// Formula.parse: all tokens are read first, so a short token raises even for a cell never stringified.
pub(crate) fn parse(data: &[u8], expired: &dyn Fn() -> bool) -> Result<Vec<Token>, XlError> {
    let mut r = DataReader::new(data);
    let mut tokens = Vec::new();
    while let Some(ptg) = r.read_byte() {
        if tokens.len() >= MAX_TOKENS {
            return Err(memory_error());
        }
        if tokens.len() & 0xFFF == 0xFFF && expired() {
            return Err(XlError::pass_timeout());
        }
        tokens.push(read_token(ptg, &mut r)?);
    }
    Ok(tokens)
}

fn read_corner(row: u32, col: u16) -> Corner {
    Corner {
        row,
        col: col & 0x3FFF,
        row_abs: col & 0x8000 == 0,
        col_abs: col & 0x4000 == 0,
    }
}

fn read_ref(r: &mut DataReader<'_>) -> Result<Corner, XlError> {
    match (r.read_int(), r.read_short()) {
        (Some(row), Some(col)) => Ok(read_corner(row, col)),
        _ => Err(type_error(NONE_AND)),
    }
}

fn read_area(r: &mut DataReader<'_>) -> Result<(Corner, Corner), XlError> {
    match (r.read_int(), r.read_int(), r.read_short(), r.read_short()) {
        (Some(r1), Some(r2), Some(c1), Some(c2)) => Ok((read_corner(r1, c1), read_corner(r2, c2))),
        _ => Err(type_error(NONE_AND)),
    }
}

fn read_token(ptg: u8, r: &mut DataReader<'_>) -> Result<Token, XlError> {
    let base = (if ptg & 0x40 == 0x40 { ptg | 0x20 } else { ptg }) & 0x3F;
    let token = match base {
        0x01 | 0x02 => {
            r.read_int();
            r.read_short();
            Token::Base(base)
        }
        0x03 => Token::Binary("+"),
        0x04 => Token::Binary("-"),
        0x05 => Token::Binary("*"),
        0x06 => Token::Binary("/"),
        0x07 => Token::Binary("^"),
        0x08 => Token::Binary("&"),
        0x09 => Token::Binary("<"),
        0x0A => Token::Binary("<="),
        0x0B => Token::Binary("="),
        0x0C => Token::Binary(">="),
        0x0D => Token::Binary(">"),
        0x0E => Token::Binary("<>"),
        0x0F => Token::Binary(" "),
        0x10 => Token::Binary(","),
        0x11 => Token::Binary(":"),
        0x12 => Token::Prefix("+"),
        0x13 => Token::Prefix("-"),
        0x14 => Token::Percent,
        0x15 => Token::Paren,
        0x16 => Token::Missing,
        0x17 => {
            let size = r.read_short();
            Token::Text(r.read_string_sized(size))
        }
        0x19 => {
            let flags = r.read_byte();
            let data = r.read_short();
            Token::Attr { flags, data }
        }
        0x1C => Token::Error(r.read_byte()),
        0x1D => Token::Bool(r.read_bool()),
        0x1E => Token::Int(r.read_short()),
        0x1F => Token::Num(r.read_double()),
        0x20 => {
            read_array(r)?;
            Token::Base(ptg)
        }
        0x21 => Token::Func(r.read_short()),
        0x22 => {
            let argc = r.read_byte();
            let idx = r.read_short();
            let (Some(argc), Some(idx)) = (argc, idx) else {
                return Err(type_error(NONE_AND));
            };
            Token::FuncVar {
                idx,
                argc: i64::from(argc & 0x7F),
            }
        }
        0x23 => {
            let idx = r.read_short();
            r.read(2);
            Token::Name(idx)
        }
        0x24 | 0x2C => Token::Ref(read_ref(r)?),
        0x25 | 0x2D => {
            let (first, last) = read_area(r)?;
            Token::Area(first, last)
        }
        0x26 => return Err(read_mem_area(r)),
        0x27 => {
            r.read(4);
            read_subex(r);
            Token::Literal("#ERR!")
        }
        0x28 => {
            r.read(4);
            read_subex(r);
            Token::Base(ptg)
        }
        0x29 | 0x2F => {
            read_subex(r);
            Token::Base(ptg)
        }
        0x2A => {
            r.read(6);
            Token::Literal("#REF!")
        }
        0x2B => {
            r.read(12);
            Token::Literal("#REF!")
        }
        0x2E => {
            // reader.skip(None) raises.
            let Some(size) = r.read_short() else {
                return Err(type_error(NONE_INT));
            };
            r.skip(usize::from(size));
            Token::Base(ptg)
        }
        0x39 => {
            r.read_short();
            r.read_short();
            r.read(2);
            Token::Base(ptg)
        }
        0x3A => {
            let extern_idx = r.read_short();
            let row = r.read_int();
            let col = r.read_short();
            let (Some(extern_idx), Some(row), Some(col)) = (extern_idx, row, col) else {
                return Err(type_error(NONE_AND));
            };
            let corner = read_corner(row, col);
            Token::Ref3d {
                extern_idx,
                row: i64::from(row),
                col: i64::from(corner.col),
                row_abs: corner.row_abs,
                col_abs: corner.col_abs,
            }
        }
        0x3B => {
            let extern_idx = r.read_short();
            let (first, last) = read_area(r)?;
            let Some(extern_idx) = extern_idx else {
                return Err(type_error(NONE_AND));
            };
            Token::Area3d(extern_idx, first, last)
        }
        0x3C => {
            r.read(8);
            Token::Literal("#REF!")
        }
        0x3D => {
            r.read(14);
            Token::Literal("#REF!")
        }
        _ => Token::Unknown(ptg),
    };
    Ok(token)
}

/// `reader.read(subex_len)`, where a None length reads the nothing that is left.
fn read_subex(r: &mut DataReader<'_>) {
    if let Some(size) = r.read_short() {
        r.read(usize::from(size));
    }
}

/// ArrayPtg.read. The values are never printed, so only the reads and the size's arithmetic matter.
fn read_array(r: &mut DataReader<'_>) -> Result<(), XlError> {
    let cols = r.read_byte();
    let rows = r.read_short();
    let (cols, rows) = match (cols, rows) {
        (None, _) => {
            return Err(type_error(
                "unsupported operand type(s) for *: 'NoneType' and 'NoneType'",
            ));
        }
        (Some(_), None) => {
            return Err(type_error(
                "unsupported operand type(s) for *: 'int' and 'NoneType'",
            ));
        }
        (Some(0), Some(rows)) => (256u32, u32::from(rows)),
        (Some(cols), Some(rows)) => (u32::from(cols), u32::from(rows)),
    };
    // Once the data ends the rest of the loop reads nothing.
    for _ in 0..cols.saturating_mul(rows) {
        if r.at_end() {
            break;
        }
        match r.read_byte() {
            Some(0x01) => {
                r.read_double();
            }
            Some(0x02) => {
                let size = r.read_short();
                r.read_string_sized(size);
            }
            _ => {}
        }
    }
    Ok(())
}

/// MemAreaPtg.read always raises: its __init__ calls object.__init__ with an argument.
fn read_mem_area(r: &mut DataReader<'_>) -> XlError {
    r.read(4);
    if r.read_short().is_some_and(|size| size != 0) && r.read_short().is_none() {
        return type_error(NONE_INT);
    }
    type_error("object.__init__() takes exactly one argument (the instance to initialize)")
}

fn cell_address(col: i64, row: i64, col_abs: bool, row_abs: bool) -> String {
    let column = crate::pyfmt::column_name_i64(col.saturating_add(1));
    let row = row.saturating_add(1);
    match (col_abs, row_abs) {
        (true, true) => format!("${column}${row}"),
        (true, false) => format!("${column}{row}"),
        (false, true) => format!("{column}${row}"),
        (false, false) => format!("{column}{row}"),
    }
}

fn corner_address(c: Corner) -> String {
    cell_address(i64::from(c.col), i64::from(c.row), c.col_abs, c.row_abs)
}

/// What an active Python stringify call is waiting for.
enum Frame {
    /// `b = tokens.pop().stringify(...)`.
    BinaryB(&'static str),
    /// `a = ...`, then `a + op + b`.
    BinaryA(&'static str, Val),
    Prefix(&'static str),
    Percent,
    Paren,
    Attr(String),
    /// A FuncVar for idx 255: `tokens[0].stringify(...).strip()`.
    UdfName(usize),
    /// A loop of pops for the arguments of a function.
    Args {
        name: String,
        left: i64,
        args: Vec<Val>,
        strip: bool,
    },
}

enum Step {
    Call(usize),
    Return(Val),
}

/// Frames on Python's stack when a formula's first token is called, and the print destination.
pub(crate) struct Ctx<'a> {
    pub(crate) book: &'a Workbook,
    pub(crate) log: &'a mut String,
    pub(crate) expired: &'a dyn Fn() -> bool,
    pub(crate) frames_above: usize,
}

struct Run<'a, 'b> {
    ctx: &'b mut Ctx<'a>,
    arena: Vec<Token>,
    list: VecDeque<usize>,
    frames: Vec<Frame>,
    /// Text held by frames. Python shares a name's formula where this holds a copy.
    held: usize,
}

/// Formula.stringify. Python's result can be None: a 3D reference it cannot place, or a None name.
pub(crate) fn stringify(tokens: Vec<Token>, ctx: &mut Ctx<'_>) -> Result<Val, XlError> {
    if tokens.is_empty() {
        return Ok(Some(String::new()));
    }
    let list = (0..tokens.len()).collect();
    let mut run = Run {
        ctx,
        arena: tokens,
        list,
        frames: Vec::new(),
        held: 0,
    };
    run.run()
}

/// Python frames a token's stringify calls before doing anything else.
fn extra_frames(token: &Token) -> usize {
    match token {
        Token::Attr { .. } => 1,
        Token::Ref(_) | Token::Area(..) | Token::Ref3d { .. } | Token::Area3d(..) => 2,
        _ => 0,
    }
}

fn checked(len: usize) -> Result<(), XlError> {
    if len > MAX_TEXT {
        return Err(memory_error());
    }
    Ok(())
}

impl Run<'_, '_> {
    fn pop(&mut self) -> Result<usize, XlError> {
        self.list
            .pop_back()
            .ok_or_else(|| index_error("pop from empty list"))
    }

    fn run(&mut self) -> Result<Val, XlError> {
        let mut step = Step::Call(self.pop()?);
        let mut work = 0usize;
        loop {
            step = match step {
                Step::Call(token) => {
                    work = work.saturating_add(1);
                    self.call(token)?
                }
                Step::Return(value) => {
                    work = work.saturating_add(value.as_ref().map_or(1, |v| v.len() >> 8));
                    let Some(frame) = self.frames.pop() else {
                        return Ok(value);
                    };
                    self.resume(frame, value)?
                }
            };
            if work >= 4096 {
                work = 0;
                if (self.ctx.expired)() {
                    return Err(XlError::pass_timeout());
                }
            }
        }
    }

    fn hold(&mut self, value: Option<&String>) -> Result<(), XlError> {
        self.held = self.held.saturating_add(value.map_or(0, String::len));
        if self.held > crate::MAX_TOTAL_TEXT {
            return Err(memory_error());
        }
        Ok(())
    }

    fn pop_into(&mut self, frame: Frame) -> Result<Step, XlError> {
        self.frames.push(frame);
        Ok(Step::Call(self.pop()?))
    }

    fn call(&mut self, index: usize) -> Result<Step, XlError> {
        let Some(token) = self.arena.get_mut(index) else {
            return Err(index_error(LIST_RANGE));
        };
        let depth = self.ctx.frames_above + self.frames.len() + 1 + extra_frames(token);
        if depth > RECURSION_LIMIT {
            return Err(XlError::new(
                "RecursionError",
                "maximum recursion depth exceeded",
            ));
        }
        let value = match token {
            Token::Binary(op) => {
                let op = *op;
                return self.pop_into(Frame::BinaryB(op));
            }
            Token::Prefix(op) => {
                let op = *op;
                return self.pop_into(Frame::Prefix(op));
            }
            Token::Percent => return self.pop_into(Frame::Percent),
            Token::Paren => return self.pop_into(Frame::Paren),
            Token::Attr { flags, data } => {
                let (flags, data) = (*flags, *data);
                return self.attr(flags, data);
            }
            Token::Func(idx) => {
                let idx = *idx;
                return self.func(idx);
            }
            Token::FuncVar { idx, argc } => {
                let (idx, argc) = (*idx, *argc);
                return self.func_var(index, idx, argc);
            }
            Token::Ref3d {
                extern_idx,
                row,
                col,
                row_abs,
                col_abs,
            } => {
                // Stringify changes the token, and the same token can be called twice.
                if !*col_abs && *col & 0x2000 == 0x2000 {
                    *col -= 16384;
                }
                if !*row_abs && *row & 0x80000 == 0x80000 {
                    *row -= 1048576;
                }
                let address = cell_address(*col, *row, *col_abs, *row_abs);
                let extern_idx = *extern_idx;
                self.ref_3d(extern_idx, address)?
            }
            Token::Area3d(extern_idx, first, last) => {
                let (extern_idx, first, last) = (*extern_idx, *first, *last);
                self.area_3d(extern_idx, first, last)?
            }
            Token::Missing => Some(String::new()),
            Token::Text(value) => {
                let Some(value) = value else {
                    return Err(none_attr("replace"));
                };
                checked(value.len().saturating_mul(2))?;
                Some(format!("\"{}\"", value.replace('"', "\"\"")))
            }
            Token::Error(value) => Some(error_text(*value).to_string()),
            Token::Bool(value) => Some(
                if value.unwrap_or(false) {
                    "TRUE"
                } else {
                    "FALSE"
                }
                .into(),
            ),
            Token::Int(value) => Some(fmt_opt(value)),
            Token::Num(value) => Some(match value {
                Some(value) => crate::pyfmt::float_str(*value),
                None => "None".to_string(),
            }),
            Token::Base(ptg) => Some(format!("#PTG{ptg}!")),
            Token::Unknown(ptg) => Some(format!("#UNK{ptg}!")),
            Token::Literal(text) => Some((*text).to_string()),
            Token::Name(idx) => {
                let idx = *idx;
                self.ctx.book.name_value(idx)?
            }
            Token::Ref(corner) => Some(corner_address(*corner)),
            Token::Area(first, last) => Some(format!(
                "{}:{}",
                corner_address(*first),
                corner_address(*last)
            )),
        };
        Ok(Step::Return(value))
    }

    fn attr(&mut self, flags: Option<u8>, data: Option<u16>) -> Result<Step, XlError> {
        let Some(flags) = flags else {
            return Err(type_error(NONE_AND));
        };
        let mut spaces = String::new();
        if flags & 0x40 == 0x40 {
            let Some(data) = data else {
                return Err(type_error(NONE_AND));
            };
            let count = usize::from(data >> 1);
            match data & 0x00FF {
                0x00 | 0x06 => spaces = " ".repeat(count),
                0x01 => spaces = "\n".repeat(count),
                _ => {}
            }
        }
        if self.list.is_empty() {
            return Ok(Step::Return(Some(spaces)));
        }
        self.pop_into(Frame::Attr(spaces))
    }

    fn func(&mut self, idx: Option<u16>) -> Result<Step, XlError> {
        let found = idx.and_then(funcs::lookup);
        let Some((name, args_no)) = found else {
            return Err(XlError::new("KeyError", fmt_opt(&idx)));
        };
        self.next_arg(
            name.to_string(),
            i64::from(args_no.unwrap_or(0)),
            Vec::new(),
            false,
        )
    }

    fn func_var(&mut self, index: usize, idx: u16, argc: i64) -> Result<Step, XlError> {
        if idx == 255 {
            let Some(&first) = self.list.front() else {
                return Err(index_error(LIST_RANGE));
            };
            self.frames.push(Frame::UdfName(index));
            return Ok(Step::Call(first));
        }
        let Some((name, _)) = funcs::lookup(idx) else {
            return Err(XlError::new("KeyError", idx.to_string()));
        };
        self.next_arg(name.to_string(), argc, Vec::new(), true)
    }

    /// The argument loop: another pop, or the formatted call once the count is reached.
    fn next_arg(
        &mut self,
        name: String,
        left: i64,
        args: Vec<Val>,
        strip: bool,
    ) -> Result<Step, XlError> {
        if left > 0 {
            return self.pop_into(Frame::Args {
                name,
                left: left - 1,
                args,
                strip,
            });
        }
        let mut joined = String::new();
        for (position, arg) in args.iter().rev().enumerate() {
            let Some(arg) = arg else {
                return Err(type_error(&format!(
                    "sequence item {position}: expected str instance, NoneType found"
                )));
            };
            if position > 0 {
                joined.push_str(", ");
            }
            checked(joined.len().saturating_add(arg.len()))?;
            joined.push_str(arg);
            self.held = self.held.saturating_sub(arg.len());
        }
        Ok(Step::Return(Some(format!("{name}({joined})"))))
    }

    fn resume(&mut self, frame: Frame, value: Val) -> Result<Step, XlError> {
        let text = match frame {
            Frame::BinaryB(op) => {
                self.hold(value.as_ref())?;
                return self.pop_into(Frame::BinaryA(op, value));
            }
            Frame::BinaryA(op, b) => {
                let Some(a) = value else {
                    return Err(type_error(NONE_PLUS_STR));
                };
                let Some(b) = b else {
                    return Err(type_error(CONCAT_NONE));
                };
                self.held = self.held.saturating_sub(b.len());
                checked(a.len().saturating_add(b.len()))?;
                format!("{a}{op}{b}")
            }
            Frame::Prefix(op) => {
                let Some(v) = value else {
                    return Err(type_error(CONCAT_NONE));
                };
                format!("{op}{v}")
            }
            Frame::Percent => {
                let Some(v) = value else {
                    return Err(type_error(NONE_PLUS_STR));
                };
                format!("{v}%")
            }
            Frame::Paren => {
                let Some(v) = value else {
                    return Err(type_error(CONCAT_NONE));
                };
                format!("({v})")
            }
            Frame::Attr(mut spaces) => {
                let Some(v) = value else {
                    return Err(type_error(CONCAT_NONE));
                };
                checked(spaces.len().saturating_add(v.len()))?;
                spaces.push_str(&v);
                spaces
            }
            Frame::UdfName(index) => {
                let Some(v) = value else {
                    return Err(none_attr("strip"));
                };
                let name = py_strip(&v).to_string();
                if self.list.pop_front().is_none() {
                    return Err(index_error(LIST_ASSIGN_RANGE));
                }
                let mut argc = 0;
                if let Some(Token::FuncVar { argc: stored, .. }) = self.arena.get_mut(index) {
                    *stored -= 1;
                    argc = *stored;
                }
                return self.next_arg(name, argc, Vec::new(), true);
            }
            Frame::Args {
                name,
                left,
                mut args,
                strip,
            } => {
                let value = if strip {
                    let Some(v) = value else {
                        return Err(none_attr("strip"));
                    };
                    Some(py_strip(&v).to_string())
                } else {
                    value
                };
                self.hold(value.as_ref())?;
                args.push(value);
                return self.next_arg(name, left, args, strip);
            }
        };
        checked(text.len())?;
        Ok(Step::Return(Some(text)))
    }

    fn ref_3d(&mut self, extern_idx: u16, cell: String) -> Result<Val, XlError> {
        let (first, last) = self.ctx.book.resolve_extern(extern_idx)?;
        let mut address = None;
        if first == last {
            let sheets = &self.ctx.book.sheets;
            match first {
                None => {
                    return Err(type_error(
                        "'>=' not supported between instances of 'NoneType' and 'int'",
                    ));
                }
                Some(n) if n >= 0 => {
                    let sheet = usize::try_from(n).ok().and_then(|i| sheets.get(i));
                    let Some(sheet) = sheet else {
                        return Err(index_error(LIST_RANGE));
                    };
                    address = Some(format!("'{}'!{cell}", fmt_opt(&sheet.name)));
                }
                Some(-1) => {
                    let Some(sheet) = sheets.last() else {
                        return Err(index_error(LIST_RANGE));
                    };
                    address = Some(format!("'{}'!{cell}", fmt_opt(&sheet.name)));
                }
                Some(-2) => address = Some(cell.clone()),
                Some(_) => {}
            }
        }
        if address.is_none() {
            self.ctx.log.push_str(&format!(
                "Ref3dPtg External Address Not Supported {cell} {} {}\n",
                fmt_opt(&first),
                fmt_opt(&last)
            ));
        }
        Ok(address)
    }

    fn area_3d(&mut self, extern_idx: u16, first: Corner, last: Corner) -> Result<Val, XlError> {
        let (cell_first, cell_last) = (corner_address(first), corner_address(last));
        let (sheet_first, sheet_last) = self.ctx.book.resolve_extern(extern_idx)?;
        let mut address = None;
        if sheet_first == sheet_last {
            match sheet_first {
                None => {
                    return Err(type_error(
                        "'>=' not supported between instances of 'NoneType' and 'int'",
                    ));
                }
                Some(n) if n >= 0 => {
                    let sheets = &self.ctx.book.sheets;
                    let sheet = usize::try_from(n).ok().and_then(|i| sheets.get(i));
                    let Some(sheet) = sheet else {
                        return Err(index_error(LIST_RANGE));
                    };
                    address = Some(format!(
                        "'{}'!{cell_first}:{cell_last}",
                        fmt_opt(&sheet.name)
                    ));
                }
                Some(_) => {}
            }
        }
        if address.is_none() {
            self.ctx.log.push_str(&format!(
                "AreaPtg External Address Not Supported {cell_first}:{cell_last} {} {}\n",
                fmt_opt(&sheet_first),
                fmt_opt(&sheet_last)
            ));
        }
        Ok(address)
    }
}

fn error_text(value: Option<u8>) -> &'static str {
    match value {
        Some(0x00) => "#NULL!",
        Some(0x07) => "#DIV/0!",
        Some(0x0F) => "#VALUE!",
        Some(0x17) => "#REF!",
        Some(0x1D) => "#NAME?",
        Some(0x24) => "#NUM!",
        Some(0x2A) => "#N/A",
        _ => "#ERR!",
    }
}
