//! pyxlsb2's datareader.py and recordreader.py with records.py: short reads give None and consume what
//! was left, and a record's `read` raises when its own arithmetic meets a None.

use crate::pyfmt::{NONE_AND, NONE_INT, memory_error, type_error};
use crate::{CellValue, XlError};

pub(crate) const ROW_HDR: u16 = 0;
pub(crate) const CELL_BLANK: u16 = 1;
const CELL_RK: u16 = 2;
const CELL_ERROR: u16 = 3;
const CELL_BOOL: u16 = 4;
const CELL_REAL: u16 = 5;
const CELL_ST: u16 = 6;
pub(crate) const CELL_ISST: u16 = 7;
const FMLA_STRING: u16 = 8;
const FMLA_NUM: u16 = 9;
const FMLA_BOOL: u16 = 10;
pub(crate) const FMLA_ERROR: u16 = 11;
pub(crate) const SST_ITEM: u16 = 19;
pub(crate) const NAME: u16 = 39;
const XF: u16 = 47;
const COL_INFO: u16 = 60;
pub(crate) const BEGIN_SHEET_DATA: u16 = 145;
pub(crate) const END_SHEET_DATA: u16 = 146;
const WS_DIM: u16 = 148;
const WB_PROP: u16 = 153;
pub(crate) const BUNDLE_SH: u16 = 156;
pub(crate) const END_SST: u16 = 160;
const END_STYLE_SHEET: u16 = 279;
pub(crate) const BEGIN_EXTERNALS: u16 = 353;
pub(crate) const SUP_BOOK_SRC: u16 = 355;
pub(crate) const SUP_SELF: u16 = 357;
pub(crate) const SUP_SAME: u16 = 358;
pub(crate) const EXTERN_SHEET: u16 = 362;
const H_LINK: u16 = 494;
const BEGIN_CELL_XFS: u16 = 617;
const END_CELL_XFS: u16 = 618;
const BEGIN_CELL_STYLE_XFS: u16 = 626;
const END_CELL_STYLE_XFS: u16 = 627;
pub(crate) const SUP_ADDIN: u16 = 667;

/// Tuples in ExternSheetRecord's list before Python, at 80 bytes a tuple, would be out of memory.
const MAX_EXTERN_SHEETS: u32 = 100_000_000;
/// Slots in Styles' two `[None] * count` lists before Python would be out of memory (8 GiB).
const MAX_STYLE_SLOTS: u64 = 1 << 30;

/// io.BytesIO under DataReader. `pos` can pass the end, as a seek does.
pub(crate) struct DataReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> DataReader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        DataReader { buf, pos: 0 }
    }

    pub(crate) fn skip(&mut self, size: usize) {
        self.pos = self.pos.saturating_add(size);
    }

    pub(crate) fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub(crate) fn read(&mut self, size: usize) -> &'a [u8] {
        let buf = self.buf;
        let Some(rest) = buf.get(self.pos..) else {
            return &[];
        };
        let (taken, _) = rest.split_at(size.min(rest.len()));
        self.pos = self.pos.saturating_add(taken.len());
        taken
    }

    fn fixed<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.read(N).try_into().ok()
    }

    pub(crate) fn read_bool(&mut self) -> Option<bool> {
        self.fixed::<1>().map(|b| b != [0])
    }

    pub(crate) fn read_byte(&mut self) -> Option<u8> {
        self.fixed::<1>().map(|[byte]| byte)
    }

    pub(crate) fn read_short(&mut self) -> Option<u16> {
        self.fixed().map(u16::from_le_bytes)
    }

    pub(crate) fn read_int(&mut self) -> Option<u32> {
        self.fixed().map(u32::from_le_bytes)
    }

    fn read_signed_int(&mut self) -> Option<i32> {
        self.fixed().map(i32::from_le_bytes)
    }

    pub(crate) fn read_double(&mut self) -> Option<f64> {
        self.fixed().map(f64::from_le_bytes)
    }

    fn read_rk(&mut self) -> Option<f64> {
        let intval: i32 = self.read_signed_int()?;
        let mut value = if intval & 0x02 == 0x02 {
            f64::from(intval >> 2)
        } else {
            let high = (intval as u32) & 0xFFFF_FFFC;
            f64::from_bits(u64::from(high) << 32)
        };
        if intval & 0x01 == 0x01 {
            value /= 100.0;
        }
        Some(value)
    }

    /// read_string(size=None): a 4-byte length, in characters.
    pub(crate) fn read_string(&mut self) -> Option<String> {
        let size = self.read_int()?;
        self.read_string_of(u64::from(size))
    }

    /// read_string(size=size) where read_short may have given None, which reads a 4-byte length.
    pub(crate) fn read_string_sized(&mut self, size: Option<u16>) -> Option<String> {
        match size {
            Some(size) => self.read_string_of(u64::from(size)),
            None => self.read_string(),
        }
    }

    fn read_string_of(&mut self, chars: u64) -> Option<String> {
        let size = usize::try_from(chars.saturating_mul(2)).unwrap_or(usize::MAX);
        let buf = self.read(size);
        (buf.len() == size).then(|| decode_utf16(buf))
    }
}

/// bytes.decode('utf-16', errors='replace') of an even length: a BOM picks the byte order, little
/// endian without one, and each unpaired surrogate becomes U+FFFD.
pub(crate) fn decode_utf16(buf: &[u8]) -> String {
    let (little, body) = match buf {
        [0xFF, 0xFE, body @ ..] => (true, body),
        [0xFE, 0xFF, body @ ..] => (false, body),
        body => (true, body),
    };
    let units = body.as_chunks::<2>().0.iter().map(|pair| {
        if little {
            u16::from_le_bytes(*pair)
        } else {
            u16::from_be_bytes(*pair)
        }
    });
    char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// ExternSheetRecord.external_sheets. Indexes come from a u16, so only the first 65536 tuples are held;
/// past the data's end they are all (None, None, None).
pub(crate) struct ExternSheets {
    count: u32,
    held: Vec<ExternEntry>,
}

pub(crate) type ExternEntry = (Option<i32>, Option<i32>, Option<i32>);

impl ExternSheets {
    pub(crate) fn get(&self, index: u16) -> Option<ExternEntry> {
        let wanted = usize::from(index);
        if u32::from(index) >= self.count {
            return None;
        }
        Some(self.held.get(wanted).copied().unwrap_or((None, None, None)))
    }
}

pub(crate) struct CellRec<'a> {
    pub(crate) col: Option<u32>,
    pub(crate) value: CellValue,
    pub(crate) formula: Option<&'a [u8]>,
    pub(crate) style: Option<u32>,
}

/// The records whose fields something reads. Other known records only keep their ability to raise.
pub(crate) enum Rec<'a> {
    Other,
    Sheet {
        r_id: Option<String>,
        name: Option<String>,
    },
    ExternSheet(ExternSheets),
    Name {
        name: Option<String>,
        raw: &'a [u8],
    },
    Row(Option<u32>),
    Cell(CellRec<'a>),
    SstItem(Option<String>),
    Count(Option<u32>),
}

pub(crate) struct RecordReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> RecordReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        RecordReader { data, pos: 0 }
    }

    pub(crate) fn tell(&self) -> usize {
        self.pos
    }

    pub(crate) fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    fn byte(&mut self) -> Option<u8> {
        let byte = self.data.get(self.pos).copied()?;
        self.pos = self.pos.saturating_add(1);
        Some(byte)
    }

    fn read_type(&mut self) -> Option<u16> {
        let first = u16::from(self.byte()?);
        if first & 0x80 == 0x80 {
            let second = u16::from(self.byte()?);
            return Some((first & 0x7F) | ((second & 0x7F) << 7));
        }
        Some(first)
    }

    fn read_len(&mut self) -> Option<usize> {
        let mut value = 0usize;
        for i in 0..4 {
            let byte = self.byte()?;
            value |= usize::from(byte & 0x7F) << (7 * i);
            if byte & 0x80 == 0 {
                break;
            }
        }
        Some(value)
    }

    /// RecordReader.next, with None for StopIteration. Polls `expired` for each record.
    pub(crate) fn next_record(
        &mut self,
        expired: &dyn Fn() -> bool,
    ) -> Result<Option<(u16, Rec<'a>)>, XlError> {
        if expired() {
            return Err(XlError::pass_timeout());
        }
        let Some(rectype) = self.read_type() else {
            return Ok(None);
        };
        let Some(reclen) = self.read_len() else {
            return Err(XlError::new(
                "RuntimeError",
                format!("incomplete record with type: {rectype}"),
            ));
        };
        let rest = self.data.get(self.pos..).unwrap_or(&[]);
        let (payload, _) = rest.split_at(reclen.min(rest.len()));
        self.pos = self.pos.saturating_add(payload.len());
        let rec = read_record(rectype, DataReader::new(payload))?;
        Ok(Some((rectype, rec)))
    }
}

fn read_record<'a>(rectype: u16, mut r: DataReader<'a>) -> Result<Rec<'a>, XlError> {
    match rectype {
        ROW_HDR => Ok(Rec::Row(r.read_int())),
        CELL_BLANK..=FMLA_ERROR => Ok(Rec::Cell(read_cell(rectype, &mut r))),
        SST_ITEM => {
            r.skip(1);
            Ok(Rec::SstItem(r.read_string()))
        }
        NAME => {
            r.read_int();
            r.read_byte();
            r.read_int();
            let name = r.read_string();
            let raw = match r.read_int() {
                Some(size) => r.read(usize::try_from(size).unwrap_or(usize::MAX)),
                None => &[],
            };
            Ok(Rec::Name { name, raw })
        }
        COL_INFO => {
            r.read_int();
            r.read_int();
            if r.read_int().is_none() {
                return Err(type_error(
                    "unsupported operand type(s) for /: 'NoneType' and 'int'",
                ));
            }
            r.read_int();
            match r.read_short() {
                Some(_) => Ok(Rec::Other),
                None => Err(type_error(NONE_AND)),
            }
        }
        WS_DIM | H_LINK => {
            let (r1, r2, c1, c2) = (r.read_int(), r.read_int(), r.read_int(), r.read_int());
            subtract_check(r2, r1)?;
            subtract_check(c2, c1)?;
            Ok(Rec::Other)
        }
        WB_PROP => match r.read_int() {
            Some(_) => Ok(Rec::Other),
            None => Err(type_error(NONE_AND)),
        },
        BUNDLE_SH => {
            let state = r.read_int();
            r.read_int();
            let r_id = r.read_string();
            let name = r.read_string();
            match state {
                Some(0..=2) => Ok(Rec::Sheet { r_id, name }),
                state => Err(XlError::new(
                    "ValueError",
                    format!(
                        "{} is not a valid SheetState",
                        crate::pyfmt::fmt_opt(&state)
                    ),
                )),
            }
        }
        EXTERN_SHEET => Ok(Rec::ExternSheet(read_extern_sheet(&mut r)?)),
        BEGIN_CELL_XFS | BEGIN_CELL_STYLE_XFS => Ok(Rec::Count(r.read_int())),
        _ => Ok(Rec::Other),
    }
}

/// `b - a + 1` of a record's two ints.
fn subtract_check(b: Option<u32>, a: Option<u32>) -> Result<(), XlError> {
    match (b, a) {
        (Some(_), _) => Ok(()),
        (None, Some(_)) => Err(type_error(
            "unsupported operand type(s) for -: 'NoneType' and 'int'",
        )),
        (None, None) => Err(type_error(
            "unsupported operand type(s) for -: 'NoneType' and 'NoneType'",
        )),
    }
}

fn read_extern_sheet(r: &mut DataReader<'_>) -> Result<ExternSheets, XlError> {
    let Some(count) = r.read_int() else {
        return Err(type_error(NONE_INT));
    };
    if count > MAX_EXTERN_SHEETS {
        return Err(memory_error());
    }
    let mut held = Vec::new();
    for _ in 0..count.min(65536) {
        if r.at_end() {
            break;
        }
        held.push((
            r.read_signed_int(),
            r.read_signed_int(),
            r.read_signed_int(),
        ));
    }
    Ok(ExternSheets { count, held })
}

fn error_value(value: Option<u8>) -> CellValue {
    CellValue::Error(format!("#ERR!{}", crate::pyfmt::fmt_opt(&value)))
}

fn opt_value<T>(value: Option<T>, wrap: impl Fn(T) -> CellValue) -> CellValue {
    value.map_or(CellValue::None, wrap)
}

fn read_cell<'a>(rectype: u16, r: &mut DataReader<'a>) -> CellRec<'a> {
    let col = r.read_int();
    let style = r.read_int();
    let value = match rectype {
        CELL_RK => opt_value(r.read_rk(), CellValue::Float),
        CELL_ERROR | FMLA_ERROR => error_value(r.read_byte()),
        CELL_BOOL | FMLA_BOOL => opt_value(r.read_bool(), CellValue::Bool),
        CELL_REAL | FMLA_NUM => opt_value(r.read_double(), CellValue::Float),
        CELL_ST | FMLA_STRING => opt_value(r.read_string(), CellValue::Text),
        CELL_ISST => opt_value(r.read_int(), |v| CellValue::Int(i64::from(v))),
        _ => CellValue::None,
    };
    let mut formula = None;
    if rectype >= FMLA_STRING {
        r.read_short();
        let size = r.read_int().unwrap_or(0);
        if size != 0 {
            let size = usize::try_from(size).unwrap_or(usize::MAX);
            let buf = r.read(size);
            if buf.len() == size {
                formula = Some(buf);
            }
        }
    }
    CellRec {
        col,
        value,
        formula,
        style,
    }
}

/// Styles._parse: nothing it keeps is read here, but its two lists and their indexing can raise.
pub(crate) fn check_styles(data: &[u8], expired: &dyn Fn() -> bool) -> Result<(), XlError> {
    let mut reader = RecordReader::new(data);
    let (mut style_slots, mut cell_slots) = (0u64, 0u64);
    while let Some((rectype, rec)) = reader.next_record(expired)? {
        match rectype {
            BEGIN_CELL_STYLE_XFS => {
                let count = xf_list(&rec, style_slots.saturating_add(cell_slots))?;
                style_slots = count;
                xf_block(&mut reader, count, END_CELL_STYLE_XFS, expired)?;
            }
            BEGIN_CELL_XFS => {
                let count = xf_list(&rec, style_slots.saturating_add(cell_slots))?;
                cell_slots = count;
                xf_block(&mut reader, count, END_CELL_XFS, expired)?;
            }
            END_STYLE_SHEET => break,
            _ => {}
        }
    }
    Ok(())
}

/// `[None] * rec.count`, given the slots still alive while it allocates.
fn xf_list(rec: &Rec<'_>, live: u64) -> Result<u64, XlError> {
    let Rec::Count(Some(count)) = rec else {
        return Err(type_error(
            "can't multiply sequence by non-int of type 'NoneType'",
        ));
    };
    let count = u64::from(*count);
    if count.saturating_add(live) > MAX_STYLE_SLOTS {
        return Err(memory_error());
    }
    Ok(count)
}

fn xf_block(
    reader: &mut RecordReader<'_>,
    count: u64,
    end: u16,
    expired: &dyn Fn() -> bool,
) -> Result<(), XlError> {
    let mut used = 0u64;
    while let Some((rectype, _)) = reader.next_record(expired)? {
        if rectype == XF {
            if used >= count {
                return Err(crate::pyfmt::index_error(crate::pyfmt::LIST_ASSIGN_RANGE));
            }
            used = used.saturating_add(1);
        } else if rectype == end {
            break;
        }
    }
    Ok(())
}
