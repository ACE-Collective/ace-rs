//! sheet.py: Sheet.read and put_cell. Cells are sparse where Python pads a dense matrix; the row
//! lengths are kept so that what Python would index or refuse stays the same.

use std::collections::HashMap;
use std::sync::Arc;

use crate::CellValue;
use crate::book::{Loader, XL_CONTINUE, XL_FORMAT2, Xf};
use crate::py::{
    R, ascii_str, assertion, byte_at, err, f64_at, from, hex_char_dump, i32_at, list_index_error,
    need, repr_bytes, slice, span, u8_at, u16_at, u32_at, unpack_string, unpack_string_update_pos,
    unpack_unicode, unpack_unicode_update_pos, utf16le, xlrd_err,
};

const XL_STRING: u16 = 0x207;
const XL_STRING_B2: u16 = 0x7;
const XL_ARRAY: u16 = 0x221;
const XL_SHRFMLA: u16 = 0x4bc;
const XL_QUICKTIP: u16 = 0x800;

pub(crate) struct CellData {
    pub(crate) value: CellValue,
    pub(crate) formula: Option<String>,
    pub(crate) xf_index: i32,
}

pub(crate) struct Sheet {
    pub(crate) name: String,
    pub(crate) number: usize,
    pub(crate) boundsheet_type: u16,
    biff_version: i32,
    position: i64,
    nrows: i64,
    ncols: i64,
    first_full_rowx: i64,
    utter_max_rows: i64,
    pub(crate) row_lens: Vec<u32>,
    pub(crate) cells: HashMap<(u32, u32), CellData>,
    /// used_cells in first insertion order: enough to rebuild the set's iteration order.
    pub(crate) insertion: Vec<(u32, u32)>,
    pub(crate) rowinfo: HashMap<i64, (i64, i64)>,
    colmap: HashMap<i64, usize>,
    colobjs: Vec<i64>,
    pub(crate) default_row_height: Option<i64>,
    ixfe: Option<i64>,
    cell_attr_to_xfx: HashMap<Vec<u8>, i64>,
    merged: Vec<(i64, i64, i64, i64)>,
    hyperlink_last: Option<(u16, u16, u16, u16)>,
}

impl Sheet {
    pub(crate) fn new(
        biff_version: i32,
        position: i64,
        name: String,
        number: usize,
        boundsheet_type: u16,
    ) -> Self {
        Sheet {
            name,
            number,
            boundsheet_type,
            biff_version,
            position,
            nrows: 0,
            ncols: 0,
            first_full_rowx: -1,
            utter_max_rows: if biff_version >= 80 { 65536 } else { 16384 },
            row_lens: Vec::new(),
            cells: HashMap::new(),
            insertion: Vec::new(),
            rowinfo: HashMap::new(),
            colmap: HashMap::new(),
            colobjs: Vec::new(),
            default_row_height: None,
            ixfe: None,
            cell_attr_to_xfx: HashMap::new(),
            merged: Vec::new(),
            hyperlink_last: None,
        }
    }

    /// `xfx` as read from _cell_xf_indexes, then Sheet.cell_xf_index's fallbacks, which key on the
    /// raw (maybe negative) indexes.
    pub(crate) fn xf_fallback(&self, xfx: i64, rowx: i128, colx: i128) -> i64 {
        if xfx > -1 {
            return xfx;
        }
        if let Ok(r) = i64::try_from(rowx)
            && let Some((_, x)) = self.rowinfo.get(&r)
            && *x > -1
        {
            return *x;
        }
        if let Ok(c) = i64::try_from(colx)
            && let Some(&i) = self.colmap.get(&c)
        {
            let x = self.colobjs.get(i).copied().unwrap_or(-1);
            return if x == -1 { 15 } else { x };
        }
        15
    }

    fn colinfo_slot(&mut self, colx: i64) -> usize {
        if let Some(&i) = self.colmap.get(&colx) {
            return i;
        }
        self.colobjs.push(-1);
        let i = self.colobjs.len() - 1;
        self.colmap.insert(colx, i);
        i
    }

    fn set_rowinfo(&mut self, rowx: i64, height: i64, xf_index: i64) {
        self.rowinfo.insert(rowx, (height, xf_index));
    }
}

/// `(XL_CELL_BOOLEAN, XL_CELL_ERROR)[is_err]`: only its IndexError is visible.
fn check_is_err(is_err: u8) -> R<()> {
    if is_err > 1 {
        return Err(err("IndexError", "tuple index out of range"));
    }
    Ok(())
}

/// sheet.unpack_RK.
fn unpack_rk(rk: &[u8]) -> R<f64> {
    let flags = byte_at(rk, 0)?;
    if flags & 2 != 0 {
        let i = i64::from(i32_at(need(rk, 4)?, 0)) >> 2;
        if flags & 1 != 0 {
            return Ok(i as f64 / 100.0);
        }
        return Ok(i as f64);
    }
    let rest = from(rk, 1);
    let rest = if rest.len() > 3 {
        rest.get(..3).unwrap_or(&[])
    } else {
        rest
    };
    let mut b = vec![0, 0, 0, 0, flags & 252];
    b.extend_from_slice(rest);
    let d = f64_at(need(&b, 8)?, 0);
    if flags & 1 != 0 {
        return Ok(d / 100.0);
    }
    Ok(d)
}

/// biffh.unpack_cell_range_address_list_update_pos with addr_size=8.
fn unpack_ranges(out: Option<&mut Vec<(i64, i64, i64, i64)>>, d: &[u8], pos: i64) -> R<i64> {
    let n = i64::from(u16_at(need(span(d, pos, 2), 2)?, 0));
    let mut pos = pos + 2;
    let mut sink = out;
    for _ in 0..n {
        let b = need(span(d, pos, 8), 8)?;
        if let Some(v) = sink.as_deref_mut() {
            v.push((
                i64::from(u16_at(b, 0)),
                i64::from(u16_at(b, 2)) + 1,
                i64::from(u16_at(b, 4)),
                i64::from(u16_at(b, 6)) + 1,
            ));
        }
        pos += 8;
    }
    Ok(pos)
}

/// Tracks the two locals of Sheet.read that a SHRFMLA can read before any record set them.
#[derive(Default)]
struct Locals {
    rowx: Option<i64>,
    colx: Option<i64>,
    saved_obj_id_bound: bool,
}

impl Locals {
    fn base(&self) -> R<(i64, i64)> {
        let r = self.rowx.ok_or_else(|| crate::py::unbound("rowx"))?;
        let c = self.colx.ok_or_else(|| crate::py::unbound("colx"))?;
        Ok((r, c))
    }
}

impl<'a> Loader<'a, '_> {
    /// Sheet.put_cell_unragged. `number` says ctype was None, so the XF's type is looked up.
    #[allow(clippy::too_many_arguments)]
    fn put_cell(
        &mut self,
        sh: &mut Sheet,
        rowx: i64,
        colx: i64,
        number: bool,
        value: CellValue,
        xf_index: i64,
        formula: Option<String>,
    ) -> R<()> {
        if number && !self.xf_type_known(xf_index) {
            return Err(err("KeyError", xf_index.to_string()));
        }
        let key = (rowx as u32, colx as u32);
        if !sh.cells.contains_key(&key) {
            self.limits.spend_cell()?;
            sh.insertion.push(key);
        }
        let fits = |sh: &Sheet| {
            sh.row_lens
                .get(rowx as usize)
                .is_some_and(|l| i64::from(*l) > colx)
        };
        if !fits(sh) {
            let nr = rowx + 1;
            let nc = colx + 1;
            if !(1..=256).contains(&nc) || !(1..=sh.utter_max_rows).contains(&nr) {
                return Err(assertion());
            }
            if nc > sh.ncols {
                sh.ncols = nc;
                if nr < sh.nrows {
                    sh.first_full_rowx = -2;
                } else if rowx > sh.first_full_rowx && sh.first_full_rowx > -2 {
                    sh.first_full_rowx = rowx;
                }
            }
            if nr <= sh.nrows {
                let ncols = sh.ncols;
                let trow = sh
                    .row_lens
                    .get_mut(rowx as usize)
                    .ok_or_else(list_index_error)?;
                let nextra = ncols - i64::from(*trow);
                if nextra > 0 {
                    self.limits.spend_slots(nextra)?;
                    *trow = ncols as u32;
                }
            } else {
                let count = nr - sh.nrows;
                self.limits.spend_rows(count)?;
                self.limits.spend_slots(count.saturating_mul(sh.ncols))?;
                let new_len = sh.row_lens.len() + count as usize;
                sh.row_lens.resize(new_len, sh.ncols as u32);
                sh.nrows = nr;
            }
            if !fits(sh) {
                self.log.push_str(&format!("put_cell {rowx} {colx}\n"));
                return Err(err("IndexError", "array assignment index out of range"));
            }
        }
        if xf_index > 32767 {
            self.log.push_str(&format!("put_cell {rowx} {colx}\n"));
            return Err(err(
                "OverflowError",
                "signed short integer is greater than maximum",
            ));
        }
        sh.cells.insert(
            key,
            CellData {
                value,
                formula,
                xf_index: xf_index as i32,
            },
        );
        Ok(())
    }

    /// Sheet.tidy_dimensions.
    fn tidy_dimensions(&mut self, sh: &mut Sheet) -> R<()> {
        if !sh.merged.is_empty() {
            let (mut nr, mut nc) = (0i64, 0i64);
            let umaxrows = sh.utter_max_rows;
            let ranges = std::mem::take(&mut sh.merged);
            for &(rlo, rhi, clo, chi) in &ranges {
                if !(0 <= rlo && rlo < rhi && rhi <= umaxrows)
                    || !(0 <= clo && clo < chi && chi <= 256)
                {
                    self.log.push_str(&format!(
                        "*** WARNING: sheet #{} ({}), MERGEDCELLS bad range ({rlo}, {rhi}, {clo}, {chi})\n",
                        sh.number,
                        ascii_str(&sh.name)
                    ));
                }
                nr = nr.max(rhi);
                nc = nc.max(chi);
            }
            if nc > sh.ncols {
                sh.ncols = nc;
                sh.first_full_rowx = -2;
            }
            if nr > sh.nrows {
                let empty = CellValue::Text(self.limits.empty_text());
                self.put_cell(sh, nr - 1, 0, false, empty, -1, None)?;
            }
        }
        let ncols = sh.ncols;
        let ubound = if sh.first_full_rowx == -2 {
            sh.nrows
        } else {
            sh.first_full_rowx
        };
        for rowx in 0..ubound.max(0) {
            let trow = sh
                .row_lens
                .get_mut(rowx as usize)
                .ok_or_else(list_index_error)?;
            let nextra = ncols - i64::from(*trow);
            if nextra > 0 {
                self.limits.spend_slots(nextra)?;
                *trow = ncols as u32;
            }
        }
        Ok(())
    }

    /// Sheet.read.
    pub(crate) fn read_sheet(&mut self, sh: &mut Sheet) -> R<()> {
        let oldpos = self.position;
        self.position = sh.position;
        let bv = sh.biff_version;
        let mut lo = Locals::default();
        let blank = self.limits.empty_text();
        loop {
            self.poll()?;
            let (rc, data_len, data) = self.get_record_parts()?;
            match rc {
                0x203 => {
                    let b = need(slice(data, 0, 14), 14)?;
                    let (r, c, x) = cell_head(b);
                    lo.rowx = Some(r);
                    lo.colx = Some(c);
                    let d = f64_at(b, 6);
                    self.put_cell(sh, r, c, true, CellValue::Float(d), x, None)?;
                }
                0xfd => {
                    let b = need(data, 10)?;
                    let (r, c, x) = cell_head(b);
                    lo.rowx = Some(r);
                    lo.colx = Some(c);
                    let sst = i32_at(b, 6);
                    let s = crate::py::py_index(i128::from(sst), self.sharedstrings.len())
                        .and_then(|i| self.sharedstrings.get(i))
                        .cloned()
                        .ok_or_else(list_index_error)?;
                    self.put_cell(sh, r, c, false, CellValue::Text(s), x, None)?;
                }
                0x204 => {
                    let b = need(slice(data, 0, 6), 6)?;
                    let (r, c, x) = cell_head(b);
                    lo.rowx = Some(r);
                    lo.colx = Some(c);
                    let strg = if bv < 80 {
                        let enc = self.encoding_or_derive()?;
                        unpack_string(data, 6, enc.as_ref(), 2)?
                    } else {
                        unpack_unicode(data, 6, 2)?
                    };
                    self.put_text(sh, r, c, strg, x)?;
                }
                0xd6 => self.record_rstring(sh, &mut lo, bv, data)?,
                0x27e => {
                    let b = need(slice(data, 0, 6), 6)?;
                    let (r, c, x) = cell_head(b);
                    lo.rowx = Some(r);
                    lo.colx = Some(c);
                    let d = unpack_rk(slice(data, 6, 10))?;
                    self.put_cell(sh, r, c, true, CellValue::Float(d), x, None)?;
                }
                0xbd => {
                    let h = need(slice(data, 0, 4), 4)?;
                    let row = i64::from(u16_at(h, 0));
                    let first = i64::from(u16_at(h, 2));
                    let last = i64::from(u16_at(need(from(data, -2), 2)?, 0));
                    let mut pos = 4i64;
                    for colx in first..=last {
                        lo.colx = Some(colx);
                        let x = i64::from(u16_at(need(span(data, pos, 2), 2)?, 0));
                        let d = unpack_rk(span(data, pos + 2, 4))?;
                        pos += 6;
                        self.put_cell(sh, row, colx, true, CellValue::Float(d), x, None)?;
                    }
                }
                0x208 => {
                    let b = need(slice(data, 0, 16), 16)?;
                    let rowx = i64::from(u16_at(b, 0));
                    lo.rowx = Some(rowx);
                    let bits1 = i64::from(u16_at(b, 6));
                    let bits2 = i64::from(u32_at(b, 12));
                    if rowx >= sh.utter_max_rows {
                        self.log.push_str(&format!(
                            "*** NOTE: ROW record has row index {rowx}; should have 0 <= rowx < {} -- record ignored!\n",
                            sh.utter_max_rows
                        ));
                        continue;
                    }
                    let xf = if (bits2 >> 7) & 1 != 0 {
                        (bits2 >> 16) & 0xfff
                    } else {
                        -1
                    };
                    sh.set_rowinfo(rowx, bits1 & 0x7fff, xf);
                }
                0x06 | 0x206 | 0x406 => self.record_formula(sh, &mut lo, bv, data)?,
                0x205 => {
                    let b = need(slice(data, 0, 8), 8)?;
                    let (r, c, x) = cell_head(b);
                    lo.rowx = Some(r);
                    lo.colx = Some(c);
                    let value = i64::from(u8_at(b, 6));
                    check_is_err(u8_at(b, 7))?;
                    self.put_cell(sh, r, c, false, CellValue::Int(value), x, None)?;
                }
                0x7d => {
                    let b = need(slice(data, 0, 10), 10)?;
                    let first = i64::from(u16_at(b, 0));
                    let last = i64::from(u16_at(b, 2));
                    let xf = i64::from(u16_at(b, 6));
                    if !(first <= last && last <= 256) {
                        self.log.push_str(&format!(
                            "*** NOTE: COLINFO record has first col index {first}, last {last}; should have 0 <= first <= last <= 255 -- record ignored!\n"
                        ));
                        continue;
                    }
                    sh.colobjs.push(xf);
                    let obj = sh.colobjs.len() - 1;
                    for colx in first..=last {
                        lo.colx = Some(colx);
                        if colx > 255 {
                            break;
                        }
                        sh.colmap.insert(colx, obj);
                    }
                }
                0x55 => {
                    need(slice(data, 0, 2), 2)?;
                }
                0x99 => {
                    if data_len != 2 {
                        self.log.push_str(&format!(
                            "*** ERROR *** STANDARDWIDTH {data_len} {}\n",
                            repr_bytes(data)
                        ));
                    }
                    need(slice(data, 0, 2), 2)?;
                }
                0xab => {
                    if data_len != 34 || slice(data, 0, 2) != b"\x20\x00" {
                        return Err(assertion());
                    }
                    need(slice(data, 2, 34), 32)?;
                }
                0x201 => {
                    let b = need(slice(data, 0, 6), 6)?;
                    let (r, c, x) = cell_head(b);
                    lo.rowx = Some(r);
                    lo.colx = Some(c);
                    self.put_cell(sh, r, c, false, CellValue::Text(blank.clone()), x, None)?;
                }
                0xbe => {
                    let nitems = data_len >> 1;
                    let b = need(data, (nitems * 2) as usize)?;
                    if nitems < 2 {
                        return Err(err(
                            "ValueError",
                            format!("not enough values to unpack (expected 2, got {nitems})"),
                        ));
                    }
                    let rowx = i64::from(u16_at(b, 0));
                    let first = i64::from(u16_at(b, 2));
                    lo.rowx = Some(rowx);
                    let last = i64::from(u16_at(b, ((nitems - 1) * 2) as usize));
                    if nitems != last + 4 - first {
                        return Err(assertion());
                    }
                    for (k, colx) in (first..=last).enumerate() {
                        lo.colx = Some(colx);
                        let x = i64::from(u16_at(b, (k + 2) * 2));
                        self.put_cell(
                            sh,
                            rowx,
                            colx,
                            false,
                            CellValue::Text(blank.clone()),
                            x,
                            None,
                        )?;
                    }
                }
                0x200 | 0x00 => {
                    if data_len == 0 {
                        continue;
                    }
                    if bv < 80 {
                        need(slice(data, 2, 8), 6)?;
                    } else {
                        need(slice(data, 4, 12), 8)?;
                    }
                    sh.nrows = 0;
                    sh.ncols = 0;
                    if matches!(bv, 21 | 30 | 40) && !self.xf_list.is_empty() {
                        self.xf_epilogue_done = true;
                    }
                }
                0x1b8 => self.handle_hlink(sh, data)?,
                0x800 => self.handle_quicktip(sh, data)?,
                0x0a => break,
                0x5d => self.handle_obj(sh, &mut lo, data)?,
                0xec => {}
                0x1b6 => {
                    if self.handle_txo(sh, data)? && !lo.saved_obj_id_bound {
                        return Err(crate::py::unbound("saved_obj_id"));
                    }
                }
                0x1c => self.handle_note(sh, data)?,
                0x872 => {}
                0x809 | 0x409 | 0x209 | 0x09 => {
                    let b = need(slice(data, 0, 4), 4)?;
                    let (version, boftype) = (u16_at(b, 0), u16_at(b, 2));
                    if boftype != 0x20 {
                        self.log.push_str(&format!(
                            "*** Unexpected embedded BOF (0x{rc:04x}) at offset {}: version=0x{version:04x} type=0x{boftype:04x}\n",
                            self.position - data_len - 4
                        ));
                    }
                    loop {
                        self.poll()?;
                        let (code, _, _) = self.get_record_parts()?;
                        if code == 0x0a {
                            break;
                        }
                    }
                }
                0x8c => self.handle_country(data)?,
                0x15f => {
                    let pos = unpack_ranges(None, data, 0)?;
                    let pos = unpack_ranges(None, data, pos)?;
                    if pos != data_len {
                        return Err(assertion());
                    }
                }
                XL_ARRAY => {
                    let b = need(slice(data, 0, 14), 14)?;
                    self.log.push_str(&format!(
                        "ARRAY: {} {} {} {} {}\n",
                        u16_at(b, 0),
                        u16_at(b, 2),
                        u8_at(b, 4),
                        u8_at(b, 5),
                        u8_at(b, 6)
                    ));
                }
                XL_SHRFMLA => {
                    let b = need(slice(data, 0, 10), 10)?;
                    self.log.push_str(&format!(
                        "SHRFMLA (main): {} {} {} {} {}\n",
                        u16_at(b, 0),
                        u16_at(b, 2),
                        u8_at(b, 4),
                        u8_at(b, 5),
                        u8_at(b, 7)
                    ));
                    let (r, c) = lo.base()?;
                    let tokslen = i64::from(u16_at(b, 8));
                    self.decompile_formula(from(data, 10), tokslen, 2, r, c, 0)?;
                }
                0x1b0 => {
                    if bv < 80 {
                        return Err(assertion());
                    }
                    need(slice(data, 0, 12), 12)?;
                    unpack_ranges(None, data, 12)?;
                }
                0x1b1 => self.record_cf(data, data_len)?,
                0x225 => {
                    if data_len == 4 {
                        sh.default_row_height = Some(i64::from(u16_at(data, 2)));
                    } else if data_len == 2 {
                        sh.default_row_height = Some(i64::from(u16_at(need(data, 2)?, 0)));
                        self.log.push_str(
                            "*** WARNING: DEFAULTROWHEIGHT record len is 2, should be 4; assuming BIFF2 format\n",
                        );
                    } else {
                        self.log.push_str(&format!(
                            "*** WARNING: DEFAULTROWHEIGHT record len is {data_len}, should be 4; ignoring this record\n"
                        ));
                    }
                    if data_len == 4 {
                        need(data, 4)?;
                    }
                }
                0xe5 => {
                    let mut ranges = std::mem::take(&mut sh.merged);
                    let r = unpack_ranges(Some(&mut ranges), data, 0);
                    sh.merged = ranges;
                    let pos = r?;
                    if pos != data_len {
                        return Err(err(
                            "AssertionError",
                            format!("MERGEDCELLS: pos={pos} data_len={data_len}"),
                        ));
                    }
                }
                0x23e => {
                    if !(bv >= 80 && data_len >= 14) {
                        if bv < 30 {
                            return Err(assertion());
                        }
                        need(slice(data, 0, 6), 6)?;
                        need(slice(data, 6, 9), 3)?;
                    }
                }
                0xa0 => {
                    let b = need(data, 4)?;
                    let (num, den) = (i64::from(u16_at(b, 0)), i64::from(u16_at(b, 2)));
                    let result = if den != 0 { num * 100 / den } else { 0 };
                    if !(10..=400).contains(&result) {
                        self.log.push_str(&format!(
                            "WARNING *** SCL rcd sheet {}: should have 0.1 <= num/den <= 4; got {num}/{den}\n",
                            sh.number
                        ));
                    }
                }
                0x41 => {
                    need(slice(data, 0, 9), 9)?;
                }
                0x1b | 0x1a => {
                    let n = i64::from(u16_at(need(slice(data, 0, 2), 2)?, 0));
                    let each = if bv >= 80 { 6 } else { 2 };
                    if n * each + 2 != data_len {
                        return Err(assertion());
                    }
                }
                _ if bv <= 45 => self.record_old(sh, &mut lo, data, rc, data_len, &blank)?,
                _ => {}
            }
        }
        self.tidy_dimensions(sh)?;
        self.position = oldpos;
        Ok(())
    }

    fn put_text(&mut self, sh: &mut Sheet, r: i64, c: i64, strg: String, x: i64) -> R<()> {
        self.limits.spend_text(strg.len())?;
        self.put_cell(sh, r, c, false, CellValue::Text(Arc::from(strg)), x, None)
    }

    fn record_rstring(&mut self, sh: &mut Sheet, lo: &mut Locals, bv: i32, data: &[u8]) -> R<()> {
        let b = need(slice(data, 0, 6), 6)?;
        let (r, c, x) = cell_head(b);
        lo.rowx = Some(r);
        lo.colx = Some(c);
        let strg;
        let mut pos;
        if bv < 80 {
            let enc = self.encoding_or_derive()?;
            (strg, pos) = unpack_string_update_pos(data, 6, enc.as_ref(), 2, None)?;
            let nrt = i64::from(byte_at(data, pos)?);
            pos += 1;
            for _ in 0..nrt {
                need(span(data, pos, 2), 2)?;
                pos += 2;
            }
        } else {
            (strg, pos) = unpack_unicode_update_pos(data, 6, 2, None)?;
            let nrt = i64::from(u16_at(need(span(data, pos, 2), 2)?, 0));
            pos += 2;
            for _ in 0..nrt {
                need(span(data, pos, 4), 4)?;
                pos += 4;
            }
        }
        if pos != data.len() as i64 {
            return Err(assertion());
        }
        self.put_text(sh, r, c, strg, x)
    }

    fn record_formula(
        &mut self,
        sh: &mut Sheet,
        lo: &mut Locals,
        bv: i32,
        data: &'a [u8],
    ) -> R<()> {
        let head = slice(data, 0, 16);
        let (rowx, colx, xf_index, result_str): (i64, i64, i64, &[u8]);
        if bv >= 30 {
            let b = need(head, 16)?;
            (rowx, colx, xf_index) = cell_head(b);
            result_str = slice(b, 6, 14);
            lo.rowx = Some(rowx);
            lo.colx = Some(colx);
        } else {
            let b = need(head, 16)?;
            rowx = i64::from(u16_at(b, 0));
            colx = i64::from(u16_at(b, 2));
            lo.rowx = Some(rowx);
            lo.colx = Some(colx);
            xf_index = self.fixed_biff2_xfindex(sh, slice(b, 4, 7), None)?;
            result_str = slice(b, 7, 15);
        }
        let fmlalen = i64::from(u16_at(need(slice(data, 20, 22), 2)?, 0));
        let mut formula =
            self.decompile_formula(from(data, 22), fmlalen, 1, rowx, colx, sh.number as i64)?;
        if slice(result_str, 6, 8) == b"\xFF\xFF" {
            let first_byte = u8_at(result_str, 0);
            match first_byte {
                0 => {
                    let mut gotstring = false;
                    let (rc2, _l, data2) = self.get_record_parts()?;
                    let mut string_data = data2;
                    if rc2 == XL_STRING || rc2 == XL_STRING_B2 {
                        gotstring = true;
                    } else if rc2 == XL_ARRAY {
                        let b = need(slice(data2, 0, 14), 14)?;
                        self.log.push_str(&format!(
                            "ARRAY: {} {} {} {} {}\n",
                            u16_at(b, 0),
                            u16_at(b, 2),
                            u8_at(b, 4),
                            u8_at(b, 5),
                            u8_at(b, 6)
                        ));
                    } else if rc2 == XL_SHRFMLA {
                        let b = need(slice(data2, 0, 10), 10)?;
                        self.log.push_str(&format!(
                            "SHRFMLA (sub): {} {} {} {} {}\n",
                            u16_at(b, 0),
                            u16_at(b, 2),
                            u8_at(b, 4),
                            u8_at(b, 5),
                            u8_at(b, 7)
                        ));
                        let tokslen = i64::from(u16_at(b, 8));
                        formula =
                            self.decompile_formula(from(data2, 10), tokslen, 2, rowx, colx, 0)?;
                    } else if !matches!(rc2, 0x236 | 0x37 | 0x21 | 0x36) {
                        return Err(xlrd_err(format!(
                            "Expected SHRFMLA, ARRAY, TABLEOP* or STRING record; found 0x{rc2:04x}"
                        )));
                    }
                    if !gotstring {
                        let (rc3, _l, d3) = self.get_record_parts()?;
                        if rc3 != XL_STRING && rc3 != XL_STRING_B2 {
                            return Err(xlrd_err(format!(
                                "Expected STRING record; found 0x{rc3:04x}"
                            )));
                        }
                        string_data = d3;
                    }
                    let strg = self.string_record_contents(sh, string_data)?;
                    self.limits.spend_text(strg.len())?;
                    self.put_cell(
                        sh,
                        rowx,
                        colx,
                        false,
                        CellValue::Text(Arc::from(strg)),
                        xf_index,
                        formula,
                    )
                }
                1 | 2 => {
                    let value = i64::from(u8_at(result_str, 2));
                    self.put_cell(
                        sh,
                        rowx,
                        colx,
                        false,
                        CellValue::Int(value),
                        xf_index,
                        formula,
                    )
                }
                3 => {
                    let t = self.limits.empty_text();
                    self.put_cell(sh, rowx, colx, false, CellValue::Text(t), xf_index, formula)
                }
                _ => Err(xlrd_err(format!(
                    "unexpected special case (0x{first_byte:02x}) in FORMULA"
                ))),
            }
        } else {
            let d = f64_at(need(result_str, 8)?, 0);
            self.put_cell(sh, rowx, colx, true, CellValue::Float(d), xf_index, formula)
        }
    }

    /// Sheet.string_record_contents.
    fn string_record_contents(&mut self, sh: &Sheet, first: &'a [u8]) -> R<String> {
        let bv = sh.biff_version;
        let lenlen = if bv >= 30 { 2i64 } else { 1 };
        let mut data = first;
        let head = need(slice(data, 0, lenlen), lenlen as usize)?;
        let expected = if lenlen == 1 {
            i64::from(u8_at(head, 0))
        } else {
            i64::from(u16_at(head, 0))
        };
        let mut offset = lenlen;
        let enc = if bv < 80 {
            self.encoding_or_derive()?
        } else {
            None
        };
        let mut found = 0i64;
        let mut result = String::new();
        loop {
            let chunk = if bv >= 80 {
                let flag = byte_at(data, offset)? & 1;
                offset += 1;
                if flag != 0 {
                    utf16le(from(data, offset))?
                } else {
                    crate::py::latin1(from(data, offset))
                }
            } else {
                crate::py::decode_opt(from(data, offset), enc.as_ref())?
            };
            found += chunk.chars().count() as i64;
            result.push_str(&chunk);
            if found == expected {
                return Ok(result);
            }
            if found > expected {
                return Err(xlrd_err(format!(
                    "STRING/CONTINUE: expected {expected} chars, found {found}"
                )));
            }
            let (rc, _l, d) = self.get_record_parts()?;
            if rc != XL_CONTINUE {
                return Err(xlrd_err(format!(
                    "Expected CONTINUE record; found record-type 0x{rc:04X}"
                )));
            }
            data = d;
            offset = 0;
        }
    }

    fn record_cf(&mut self, data: &[u8], data_len: i64) -> R<()> {
        let b = need(slice(data, 0, 10), 10)?;
        let sz1 = i64::from(u16_at(b, 2));
        let sz2 = i64::from(u16_at(b, 4));
        let flags = u32_at(b, 6);
        let mut pos = 12i64;
        if (flags >> 26) & 1 != 0 {
            need(span(data, pos, 118), 118)?;
            pos += 118;
        }
        if (flags >> 28) & 1 != 0 {
            pos += 8;
        }
        if (flags >> 29) & 1 != 0 {
            pos += 4;
        }
        pos += sz1 + sz2;
        if pos != data_len {
            return Err(assertion());
        }
        Ok(())
    }

    /// The `elif bv <= 45` branch of Sheet.read: records only BIFF4W and older have.
    fn record_old(
        &mut self,
        sh: &mut Sheet,
        lo: &mut Locals,
        data: &'a [u8],
        rc: u16,
        data_len: i64,
        blank: &Arc<str>,
    ) -> R<()> {
        match rc {
            0x41e | XL_FORMAT2 => self.handle_format(data, rc)?,
            0x31 | 0x231 => self.handle_font(data)?,
            0x293 => {
                self.xf_epilogue_done = true;
                self.handle_style(data)?;
            }
            0x92 => self.handle_palette(data)?,
            0x56 => {
                need(slice(data, 0, 2), 2)?;
            }
            0x443 | 0x243 | 0x43 => self.handle_xf(data)?,
            0x22 => self.handle_datemode(data)?,
            0x42 => self.handle_codepage(data)?,
            0x2f => return Err(xlrd_err("Workbook is encrypted")),
            0x5c => self.handle_writeaccess(data)?,
            0x44 => sh.ixfe = Some(i64::from(u16_at(need(data, 2)?, 0))),
            0x03 => {
                let b = need(data, 15)?;
                let (r, c) = (i64::from(u16_at(b, 0)), i64::from(u16_at(b, 2)));
                lo.rowx = Some(r);
                lo.colx = Some(c);
                let d = f64_at(b, 7);
                let x = self.fixed_biff2_xfindex(sh, slice(b, 4, 7), None)?;
                self.put_cell(sh, r, c, true, CellValue::Float(d), x, None)?;
            }
            0x02 => {
                let b = need(data, 9)?;
                let (r, c) = (i64::from(u16_at(b, 0)), i64::from(u16_at(b, 2)));
                lo.rowx = Some(r);
                lo.colx = Some(c);
                let d = f64::from(u16_at(b, 7));
                let x = self.fixed_biff2_xfindex(sh, slice(b, 4, 7), None)?;
                self.put_cell(sh, r, c, true, CellValue::Float(d), x, None)?;
            }
            0x04 => {
                let b = need(slice(data, 0, 7), 7)?;
                let (r, c) = (i64::from(u16_at(b, 0)), i64::from(u16_at(b, 2)));
                lo.rowx = Some(r);
                lo.colx = Some(c);
                let enc = self.encoding_or_derive()?;
                let strg = unpack_string(data, 7, enc.as_ref(), 1)?;
                let x = self.fixed_biff2_xfindex(sh, slice(b, 4, 7), None)?;
                self.put_text(sh, r, c, strg, x)?;
            }
            0x05 => {
                let b = need(data, 9)?;
                let (r, c) = (i64::from(u16_at(b, 0)), i64::from(u16_at(b, 2)));
                lo.rowx = Some(r);
                lo.colx = Some(c);
                check_is_err(u8_at(b, 8))?;
                let x = self.fixed_biff2_xfindex(sh, slice(b, 4, 7), None)?;
                let v = i64::from(u8_at(b, 7));
                self.put_cell(sh, r, c, false, CellValue::Int(v), x, None)?;
            }
            0x01 => {
                let b = need(slice(data, 0, 7), 7)?;
                let (r, c) = (i64::from(u16_at(b, 0)), i64::from(u16_at(b, 2)));
                lo.rowx = Some(r);
                lo.colx = Some(c);
                let x = self.fixed_biff2_xfindex(sh, slice(b, 4, 7), None)?;
                self.put_cell(sh, r, c, false, CellValue::Text(blank.clone()), x, None)?;
            }
            0x45 => self.handle_efont(data)?,
            0x08 => {
                let b = need(slice(data, 0, 11), 11)?;
                let rowx = i64::from(u16_at(b, 0));
                lo.rowx = Some(rowx);
                let bits1 = i64::from(u16_at(b, 6));
                let bits2 = u8_at(b, 10);
                if rowx >= sh.utter_max_rows {
                    self.log.push_str(&format!(
                        "*** NOTE: ROW_B2 record has row index {rowx}; should have 0 <= rowx < {} -- record ignored!\n",
                        sh.utter_max_rows
                    ));
                    return Ok(());
                }
                let xf = if bits2 & 1 == 0 {
                    -1
                } else if data_len == 18 {
                    let xfx = i64::from(u16_at(need(slice(data, 16, 18), 2)?, 0));
                    self.fixed_biff2_xfindex(sh, &[], Some(xfx))?
                } else {
                    self.fixed_biff2_xfindex(sh, slice(data, 13, 16), None)?
                };
                sh.set_rowinfo(rowx, bits1 & 0x7fff, xf);
            }
            0x24 => {
                let b = need(slice(data, 0, 4), 4)?;
                let (first, last) = (i64::from(u8_at(b, 0)), i64::from(u8_at(b, 1)));
                if first > last {
                    self.log.push_str(&format!(
                        "*** NOTE: COLWIDTH record has first col index {first}, last {last}; should have first <= last -- record ignored!\n"
                    ));
                    return Ok(());
                }
                for colx in first..=last {
                    lo.colx = Some(colx);
                    sh.colinfo_slot(colx);
                }
            }
            0x20 => {
                let b = need(slice(data, 0, 4), 4)?;
                let first = i64::from(u16_at(b, 0));
                let mut last = i64::from(u16_at(b, 2));
                if !(first < last && last <= 256) {
                    self.log.push_str(&format!(
                        "*** NOTE: COLUMNDEFAULT record has first col index {first}, last {last}; should have 0 <= first < last <= 256\n"
                    ));
                    last = last.min(256);
                }
                for colx in first..last {
                    lo.colx = Some(colx);
                    let offset = 4 + 3 * (colx - first);
                    let x = self.fixed_biff2_xfindex(sh, span(data, offset, 3), None)?;
                    let slot = sh.colinfo_slot(colx);
                    if let Some(v) = sh.colobjs.get_mut(slot) {
                        *v = x;
                    }
                }
            }
            0x3e => {
                need(slice(data, 5, 10), 5)?;
                need(slice(data, 10, 13), 3)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Sheet.fixed_BIFF2_xfindex; `true_xfx` is its keyword of that name.
    fn fixed_biff2_xfindex(
        &mut self,
        sh: &mut Sheet,
        cell_attr: &[u8],
        true_xfx: Option<i64>,
    ) -> R<i64> {
        if sh.biff_version == 21 {
            if !self.xf_list.is_empty() {
                let mut xfx = match true_xfx {
                    Some(x) => x,
                    None => i64::from(byte_at(cell_attr, 0)? & 0x3F),
                };
                if xfx == 0x3F {
                    xfx = sh.ixfe.ok_or_else(|| {
                        xlrd_err("BIFF2 cell record has XF index 63 but no preceding IXFE record.")
                    })?;
                }
                return Ok(xfx);
            }
            sh.biff_version = 20;
            self.biff_version = 20;
        }
        if true_xfx.is_some() {
            // The ROW_B2 caller passes cell_attr=None with true_xfx.
            return Err(err("TypeError", "'NoneType' object is not subscriptable"));
        }
        if byte_at(cell_attr, 0)? & 0x3F != 0 {
            return Err(assertion());
        }
        if let Some(&x) = sh.cell_attr_to_xfx.get(cell_attr) {
            return Ok(x);
        }
        if self.xf_list.is_empty() {
            for _ in 0..16 {
                self.insert_new_biff20_xf(sh, b"\x40\x00\x00")?;
            }
        }
        self.insert_new_biff20_xf(sh, cell_attr)
    }

    fn insert_new_biff20_xf(&mut self, sh: &mut Sheet, cell_attr: &[u8]) -> R<i64> {
        let xfx = self.xf_list.len() as i64;
        let b = need(cell_attr, 3)?;
        let font_and_format = i64::from(u8_at(b, 1));
        let halign = i64::from(u8_at(b, 2));
        let format_key = font_and_format & 0x3F;
        let side = |m: i64| if halign & m != 0 { 8 } else { 0 };
        self.xf_list.push(Xf {
            font_index: (font_and_format & 0xC0) >> 6,
            hor_align: halign & 0x07,
            vert_align: 2,
            pattern_colour_index: 8,
            background_colour_index: 9,
            border_colours: [side(0x40), 0, side(0x08), side(0x10), side(0x20)],
        });
        if !self.format_keys.contains(&format_key) {
            if format_key != 0 {
                self.log.push_str(&format!(
                    "ERROR *** XF[{xfx}] unknown format key ({format_key}, 0x{format_key:04x})\n"
                ));
            }
            self.format_keys.insert(format_key);
        }
        sh.cell_attr_to_xfx.insert(cell_attr.to_vec(), xfx);
        Ok(xfx)
    }

    fn handle_hlink(&mut self, sh: &mut Sheet, data: &[u8]) -> R<()> {
        let record_size = data.len() as i64;
        let b = need(slice(data, 0, 32), 32)?;
        let frowx = u16_at(b, 0);
        let lrowx = u16_at(b, 2);
        let fcolx = u16_at(b, 4);
        let lcolx = u16_at(b, 6);
        if slice(b, 8, 24) != b"\xD0\xC9\xEA\x79\xF9\xBA\xCE\x11\x8C\x82\x00\xAA\x00\x4B\xA9\x0B"
            || slice(b, 24, 28) != b"\x02\x00\x00\x00"
        {
            return Err(assertion());
        }
        let options = u32_at(b, 28);
        let mut offset = 32i64;
        if options & 0x14 != 0 {
            offset = nul_terminated(data, offset)?;
        }
        if options & 0x80 != 0 {
            offset = nul_terminated(data, offset)?;
        }
        if options & 1 != 0 && options & 0x100 == 0 {
            let clsid = need(span(data, offset, 16), 16)?;
            offset += 16;
            if clsid == b"\xE0\xC9\xEA\x79\xF9\xBA\xCE\x11\x8C\x82\x00\xAA\x00\x4B\xA9\x0B" {
                let nbytes = i64::from(u32_at(need(span(data, offset, 4), 4)?, 0));
                offset += 4;
                let url = utf16le(span(data, offset, nbytes))?;
                let endpos = url.chars().position(|c| c == '\0').map_or(-1, |p| p as i64);
                let true_nbytes = 2 * (endpos + 1);
                offset += true_nbytes;
                let extra = nbytes - true_nbytes;
                offset += extra;
                if extra != 24 && extra != 0 {
                    return Err(assertion());
                }
            } else if clsid == b"\x03\x03\x00\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46" {
                let h = need(span(data, offset, 6), 6)?;
                let nbytes = i64::from(i32_at(h, 2));
                offset += 6;
                offset += nbytes;
                offset += 24;
                let sz = i32_at(need(span(data, offset, 4), 4)?, 0);
                offset += 4;
                if sz != 0 {
                    let xl = i64::from(i32_at(need(span(data, offset, 4), 4)?, 0));
                    offset += 4;
                    offset += 2;
                    utf16le(slice(data, offset, offset + xl))?;
                    offset += xl;
                }
            } else {
                self.log
                    .push_str(&format!("*** unknown clsid {}\n", repr_bytes(clsid)));
            }
        } else if options & 0x163 == 0x103 {
            offset = nul_terminated(data, offset)?;
        }
        if options & 0x8 != 0 {
            offset = nul_terminated(data, offset)?;
        }
        let extra = record_size - offset;
        if extra > 0 {
            self.log.push_str(&format!(
                "*** WARNING: hyperlink at R{}C{} has {extra} extra data bytes: {}\n",
                i64::from(frowx) + 1,
                i64::from(fcolx) + 1,
                repr_bytes(from(data, -extra))
            ));
        } else if extra < 0 {
            return Err(xlrd_err(
                "Bug or corrupt file, send copy of input file for debugging",
            ));
        }
        sh.hyperlink_last = Some((frowx, lrowx, fcolx, lcolx));
        Ok(())
    }

    fn handle_quicktip(&mut self, sh: &Sheet, data: &[u8]) -> R<()> {
        let b = need(slice(data, 0, 10), 10)?;
        if u16_at(b, 0) != XL_QUICKTIP {
            return Err(assertion());
        }
        let last = sh.hyperlink_last.ok_or_else(assertion)?;
        if (u16_at(b, 2), u16_at(b, 4), u16_at(b, 6), u16_at(b, 8)) != last
            || from(data, -2) != b"\x00\x00"
        {
            return Err(assertion());
        }
        utf16le(slice(data, 10, -2))?;
        Ok(())
    }

    fn handle_obj(&mut self, sh: &Sheet, lo: &mut Locals, data: &[u8]) -> R<()> {
        lo.saved_obj_id_bound = true;
        if sh.biff_version < 80 {
            return Ok(());
        }
        let data_len = data.len() as i64;
        let mut pos = 0i64;
        let mut autofilter = false;
        let mut has_id = false;
        while pos < data_len {
            let h = need(span(data, pos, 4), 4)?;
            let (ft, cb) = (u16_at(h, 0), i64::from(u16_at(h, 2)));
            if pos == 0 && !(ft == 0x15 && cb == 18) {
                return Ok(());
            }
            match ft {
                0x15 => {
                    if pos != 0 {
                        return Err(assertion());
                    }
                    let b = need(slice(data, pos + 4, pos + 10), 6)?;
                    autofilter = u16_at(b, 4) & 0x0100 != 0;
                    has_id = true;
                }
                0x00 => {
                    let rest = slice(data, pos, data_len);
                    if rest.iter().all(|c| *c == 0) {
                        break;
                    }
                    let msg = "Unexpected data at end of OBJECT record";
                    self.log.push_str(&format!("*** ERROR {msg}\n"));
                    hex_char_dump(self.log, data, pos, data_len - pos);
                    return Err(xlrd_err(msg));
                }
                0x0C => {
                    need(slice(data, pos + 8, pos + 18), 10)?;
                }
                0x13 if autofilter => break,
                _ => {}
            }
            pos += cb + 4;
        }
        if !has_id {
            return Err(err(
                "AttributeError",
                "'MSObj' object has no attribute 'id'",
            ));
        }
        Ok(())
    }

    fn handle_note(&mut self, sh: &Sheet, data: &'a [u8]) -> R<()> {
        let data_len = data.len() as i64;
        if sh.biff_version < 80 {
            let b = need(slice(data, 0, 6), 6)?;
            let mut expected = i64::from(u16_at(b, 4));
            let nb = data_len - 6;
            if nb > expected {
                return Err(assertion());
            }
            let mut pieces: Vec<u8> = from(data, 6).to_vec();
            expected -= nb;
            while expected > 0 {
                let (rc2, data2_len, data2) = self.get_record_parts()?;
                if rc2 != 0x1c {
                    return Err(assertion());
                }
                let h = need(slice(data2, 0, 6), 6)?;
                let nb2 = i64::from(u16_at(h, 4));
                if u16_at(h, 0) != 0xFFFF || nb2 != data2_len - 6 {
                    return Err(assertion());
                }
                pieces.extend_from_slice(from(data2, 6));
                expected -= nb2;
            }
            if expected != 0 {
                return Err(assertion());
            }
            let enc = self.encoding_or_derive()?;
            crate::py::decode_opt(&pieces, enc.as_ref())?;
            return Ok(());
        }
        need(slice(data, 0, 8), 8)?;
        let (_author, endpos) = unpack_unicode_update_pos(data, 8, 2, None)?;
        if !matches!(data_len - endpos, 0 | 1) {
            return Err(assertion());
        }
        Ok(())
    }

    /// Sheet.handle_txo; true where Python returns a (truthy) object.
    fn handle_txo(&mut self, sh: &Sheet, data: &[u8]) -> R<bool> {
        if sh.biff_version < 80 {
            return Ok(false);
        }
        let b = need(slice(data, 0, 16), 16)?;
        let cch_text = i64::from(u16_at(b, 10));
        let cb_runs = i64::from(u16_at(b, 12));
        let mut totchars = 0i64;
        while totchars < cch_text {
            self.poll()?;
            let (rc2, data2_len, data2) = self.get_record_parts()?;
            if rc2 != XL_CONTINUE {
                return Err(assertion());
            }
            let nb = byte_at(data2, 0)?;
            let mut nchars = data2_len - 1;
            if nb != 0 {
                if nchars % 2 != 0 {
                    return Err(assertion());
                }
                nchars /= 2;
            }
            let (_t, endpos) = unpack_unicode_update_pos(data2, 0, 2, Some(nchars))?;
            if endpos != data2_len {
                return Err(assertion());
            }
            totchars += nchars;
        }
        let mut totruns = 0i64;
        while totruns < cb_runs {
            self.poll()?;
            let (rc3, data3_len, data3) = self.get_record_parts()?;
            if rc3 != XL_CONTINUE || data3_len % 8 != 0 {
                return Err(assertion());
            }
            let mut pos = 0i64;
            while pos < data3_len {
                need(span(data3, pos, 8), 8)?;
                totruns += 8;
                pos += 8;
            }
        }
        Ok(true)
    }
}

fn nul_terminated(data: &[u8], ofs: i64) -> R<i64> {
    let nb = i64::from(u32_at(need(span(data, ofs, 4), 4)?, 0)) * 2;
    let ofs = ofs + 4;
    utf16le(span(data, ofs, nb))?;
    Ok(ofs + nb)
}

/// `rowx, colx, xf_index` from the first six bytes of a cell record.
fn cell_head(b: &[u8]) -> (i64, i64, i64) {
    (
        i64::from(u16_at(b, 0)),
        i64::from(u16_at(b, 2)),
        i64::from(u16_at(b, 4)),
    )
}
