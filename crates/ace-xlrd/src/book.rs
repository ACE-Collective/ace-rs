//! book.py and the parts of formatting.py and sheet.py's setup a parsed workbook depends on.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use indexmap::IndexMap;

use crate::compdoc::{CompDoc, Located};
use crate::formula::Name;
use crate::py::{
    Encoding, R, ascii_str, assertion, err, from, i32_at, list_index_error, memory_error, need,
    repr_bytes, slice, span, u8_at, u16_at, u32_at, unpack_string, unpack_string_update_pos,
    unpack_unicode, unpack_unicode_update_pos, xlrd_err,
};
use crate::sheet::Sheet;
use crate::{Limits, XlError};

const XL_WORKBOOK_GLOBALS: u16 = 0x5;
const XL_WORKBOOK_GLOBALS_4W: u16 = 0x100;
pub(crate) const XL_WORKSHEET: u16 = 0x10;
pub(crate) const XL_MACROSHEET: u16 = 0x40;
const SUPBOOK_INTERNAL: u8 = 1;
const SUPBOOK_ADDIN: u8 = 3;
const SUPBOOK_DDEOLE: u8 = 4;
const SUPBOOK_EXTERNAL: u8 = 2;
pub(crate) const XL_CONTINUE: u16 = 0x3c;
const XL_FORMAT: u16 = 0x41e;
pub(crate) const XL_FORMAT2: u16 = 0x1e;

/// Format keys that fill_in_standard_formats adds, from fmt_code_ranges.
const STD_FORMAT_RANGES: [(i64, i64); 12] = [
    (0, 0),
    (1, 13),
    (14, 22),
    (27, 36),
    (37, 44),
    (45, 47),
    (48, 48),
    (49, 49),
    (50, 58),
    (59, 62),
    (67, 70),
    (71, 81),
];

const BUILT_IN_STYLE_NAMES: [&str; 10] = [
    "Normal",
    "RowLevel_",
    "ColLevel_",
    "Comma",
    "Currency",
    "Percent",
    "Comma [0]",
    "Currency [0]",
    "Hyperlink",
    "Followed Hyperlink",
];

const BUILTIN_NAME_FROM_CODE: [&str; 14] = [
    "Consolidate_Area",
    "Auto_Open",
    "Auto_Close",
    "Extract",
    "Database",
    "Criteria",
    "Print_Area",
    "Print_Titles",
    "Recorder",
    "Data_Form",
    "Auto_Activate",
    "Auto_Deactivate",
    "Sheet_Title",
    "_FilterDatabase",
];

#[derive(Clone, Default)]
pub(crate) struct Font {
    pub(crate) height: i64,
    pub(crate) colour_index: i64,
}

#[derive(Clone, Default)]
pub(crate) struct Xf {
    pub(crate) font_index: i64,
    pub(crate) hor_align: i64,
    pub(crate) vert_align: i64,
    pub(crate) pattern_colour_index: i64,
    pub(crate) background_colour_index: i64,
    pub(crate) border_colours: [i64; 5],
}

/// Book's state while reading. After open only what the wrapper reads stays, in `crate::Book`.
pub(crate) struct Loader<'a, 'l> {
    pub(crate) mem: &'a [u8],
    pub(crate) base: i64,
    pub(crate) position: i64,
    pub(crate) log: &'l mut String,
    pub(crate) expired: &'l dyn Fn() -> bool,
    pub(crate) biff_version: i32,
    pub(crate) codepage: Option<i64>,
    pub(crate) encoding: Option<Encoding>,
    raw_user_name: bool,
    user_name: &'a [u8],
    pub(crate) sheet_list: Vec<Option<Sheet>>,
    pub(crate) sheet_names: Vec<String>,
    sh_abs_posn: Vec<i64>,
    sheethdr_count: i64,
    sheetsoffset: Option<i64>,
    pub(crate) sharedstrings: Vec<Arc<str>>,
    pub(crate) all_sheets_map: Vec<i64>,
    supbook_count: i64,
    pub(crate) supbook_locals_inx: Option<i64>,
    pub(crate) supbook_addins_inx: Option<i64>,
    pub(crate) externsheet_info: Vec<(u16, u16, u16)>,
    pub(crate) externsheet_type_b57: Vec<u8>,
    extnsht_name_from_num: HashMap<i64, String>,
    sheet_num_from_name: HashMap<String, i64>,
    extnsht_count: i64,
    supbook_types: Vec<Option<u8>>,
    pub(crate) addin_func_names: Vec<String>,
    pub(crate) names: Vec<Name<'a>>,
    label_names: HashSet<String>,
    countries: (u16, u16),
    pub(crate) xf_list: Vec<Xf>,
    pub(crate) font_list: Vec<Font>,
    pub(crate) format_keys: HashSet<i64>,
    xfcount: i64,
    actualfmtcount: i64,
    pub(crate) xf_epilogue_done: bool,
    pub(crate) normal_style: Option<i64>,
    palette_loaded: bool,
    colour_keys_end: i64,
    pub(crate) limits: Limits,
}

impl<'a, 'l> Loader<'a, 'l> {
    fn new(mem: &'a [u8], log: &'l mut String, expired: &'l dyn Fn() -> bool) -> Self {
        Loader {
            mem,
            base: 0,
            position: 0,
            log,
            expired,
            biff_version: 0,
            codepage: None,
            encoding: None,
            raw_user_name: false,
            user_name: &[],
            sheet_list: Vec::new(),
            sheet_names: Vec::new(),
            sh_abs_posn: Vec::new(),
            sheethdr_count: 0,
            sheetsoffset: None,
            sharedstrings: Vec::new(),
            all_sheets_map: Vec::new(),
            supbook_count: 0,
            supbook_locals_inx: None,
            supbook_addins_inx: None,
            externsheet_info: Vec::new(),
            externsheet_type_b57: Vec::new(),
            extnsht_name_from_num: HashMap::new(),
            sheet_num_from_name: HashMap::new(),
            extnsht_count: 0,
            supbook_types: Vec::new(),
            addin_func_names: Vec::new(),
            names: Vec::new(),
            label_names: HashSet::new(),
            countries: (0, 0),
            xf_list: Vec::new(),
            font_list: Vec::new(),
            format_keys: HashSet::new(),
            xfcount: 0,
            actualfmtcount: 0,
            xf_epilogue_done: false,
            normal_style: None,
            palette_loaded: false,
            colour_keys_end: 0,
            limits: Limits::default(),
        }
    }

    pub(crate) fn poll(&self) -> R<()> {
        if (self.expired)() {
            return Err(err("PassTimeout", "timed out reading the workbook"));
        }
        Ok(())
    }

    /// Book.get_record_parts.
    pub(crate) fn get_record_parts(&mut self) -> R<(u16, i64, &'a [u8])> {
        let pos = self.position;
        let mem = self.mem;
        let hdr = need(span(mem, pos, 4), 4)?;
        let code = u16_at(hdr, 0);
        let length = i64::from(u16_at(hdr, 2));
        let pos = pos + 4;
        let data = span(mem, pos, length);
        self.position = pos + length;
        Ok((code, length, data))
    }

    fn get2bytes(&mut self) -> i64 {
        let pos = self.position;
        let b = span(self.mem, pos, 2);
        self.position += b.len() as i64;
        if b.len() < 2 {
            return 0xF00BAAA;
        }
        i64::from(u16_at(b, 0))
    }

    /// Book.getbof.
    fn getbof(&mut self, rqd_stream: u16) -> R<(i32, u16)> {
        let bof_error =
            |msg: String| xlrd_err(format!("Unsupported format, or corrupt file: {msg}"));
        let savpos = self.position;
        let opcode = self.get2bytes();
        if opcode == 0xF00BAAA {
            return Err(bof_error("Expected BOF record; met end of file".into()));
        }
        let boflen = match opcode {
            0x0809 => 8i64,
            0x0409 | 0x0209 => 6,
            0x0009 => 4,
            _ => {
                return Err(bof_error(format!(
                    "Expected BOF record; found {}",
                    repr_bytes(span(self.mem, savpos, 8))
                )));
            }
        };
        let length = self.get2bytes();
        if length == 0xF00BAAA {
            return Err(bof_error(
                "Incomplete BOF record[1]; met end of file".into(),
            ));
        }
        if !(4..=20).contains(&length) {
            return Err(bof_error(format!(
                "Invalid length ({length}) for BOF record type 0x{opcode:04x}"
            )));
        }
        let data = span(self.mem, self.position, length);
        self.position += data.len() as i64;
        if (data.len() as i64) < length {
            return Err(bof_error(
                "Incomplete BOF record[2]; met end of file".into(),
            ));
        }
        let mut padded = data.to_vec();
        padded.resize(data.len().max(boflen as usize), 0);
        let version1 = opcode >> 8;
        let version2 = u16_at(&padded, 0);
        let streamtype = u16_at(&padded, 2);
        let (mut build, mut year) = (0, 0);
        let mut version = 0;
        if version1 == 0x08 {
            build = u16_at(&padded, 4);
            year = u16_at(&padded, 6);
            version = match version2 {
                0x0600 => 80,
                0x0500 => {
                    if year < 1994 || matches!(build, 2412 | 3218 | 3321) {
                        50
                    } else {
                        70
                    }
                }
                0x0000 | 0x0007 | 0x0200 => 21,
                0x0300 => 30,
                0x0400 => 40,
                _ => 0,
            };
        } else if version1 == 0x04 {
            version = 40;
        } else if version1 == 0x02 {
            version = 30;
        } else if version1 == 0x00 {
            version = 21;
        }
        if version == 40 && streamtype == XL_WORKBOOK_GLOBALS_4W {
            version = 45;
        }
        let got_globals = streamtype == XL_WORKBOOK_GLOBALS
            || (version == 45 && streamtype == XL_WORKBOOK_GLOBALS_4W);
        if (rqd_stream == XL_WORKBOOK_GLOBALS && got_globals) || streamtype == rqd_stream {
            return Ok((version, streamtype));
        }
        if version < 50 && streamtype == XL_WORKSHEET {
            return Ok((version, streamtype));
        }
        if version == 80 && streamtype == XL_MACROSHEET {
            return Ok((version, streamtype));
        }
        if version >= 50 && streamtype == 0x0100 {
            return Err(bof_error("Workspace file -- no spreadsheet data".into()));
        }
        Err(bof_error(format!(
            "BOF not workbook/worksheet: op=0x{opcode:04x} vers=0x{version2:04x} strm=0x{streamtype:04x} build={build} year={year} -> BIFF{version}"
        )))
    }

    /// Book.get_sheet.
    fn get_sheet(&mut self, sh_number: usize, update_pos: bool) -> R<()> {
        if update_pos {
            self.position = self
                .sh_abs_posn
                .get(sh_number)
                .copied()
                .ok_or_else(list_index_error)?;
        }
        let (_version, stream_type) = self.getbof(XL_WORKSHEET)?;
        let name = self
            .sheet_names
            .get(sh_number)
            .cloned()
            .ok_or_else(list_index_error)?;
        let mut sh = Sheet::new(
            self.biff_version,
            self.position,
            name,
            sh_number,
            stream_type,
        );
        self.read_sheet(&mut sh)?;
        let slot = self
            .sheet_list
            .get_mut(sh_number)
            .ok_or_else(list_index_error)?;
        *slot = Some(sh);
        Ok(())
    }

    fn get_sheets(&mut self) -> R<()> {
        for n in 0..self.sheet_names.len() {
            self.get_sheet(n, true)?;
        }
        Ok(())
    }

    fn fake_globals_get_sheet(&mut self) -> R<()> {
        self.initialise_colour_map();
        self.xf_epilogue_done = false;
        self.sheet_names = vec!["Sheet 1".to_string()];
        self.sh_abs_posn = vec![0];
        self.sheet_list.push(None);
        self.get_sheets()
    }

    fn handle_boundsheet(&mut self, data: &'a [u8]) -> R<()> {
        let bv = self.biff_version;
        self.derive_encoding()?;
        let (sheet_name, sheet_type, abs_posn);
        if bv == 45 {
            sheet_name = unpack_string(data, 0, self.encoding.as_ref(), 1)?;
            sheet_type = 0u8;
            abs_posn = if self.sh_abs_posn.is_empty() {
                let off = self.sheetsoffset.ok_or_else(|| {
                    err(
                        "AttributeError",
                        "'Book' object has no attribute '_sheetsoffset'",
                    )
                })?;
                off + self.base
            } else {
                -1
            };
        } else {
            let b = need(slice(data, 0, 6), 6)?;
            abs_posn = i64::from(i32_at(b, 0)) + self.base;
            sheet_type = u8_at(b, 5);
            sheet_name = if bv < 80 {
                unpack_string(data, 6, self.encoding.as_ref(), 1)?
            } else {
                unpack_unicode(data, 6, 1)?
            };
        }
        if sheet_type != 0 && sheet_type != 1 {
            self.all_sheets_map.push(-1);
        } else {
            let snum = self.sheet_names.len() as i64;
            self.all_sheets_map.push(snum);
            self.sheet_num_from_name.insert(sheet_name.clone(), snum);
            self.sheet_names.push(sheet_name);
            self.sh_abs_posn.push(abs_posn);
        }
        Ok(())
    }

    /// Book.derive_encoding.
    pub(crate) fn derive_encoding(&mut self) -> R<()> {
        match self.codepage {
            None => {
                if self.biff_version < 80 {
                    self.log.push_str(
                        "*** No CODEPAGE record, no encoding_override: will use 'iso-8859-1'\n",
                    );
                    self.encoding = Some(Encoding::named("iso-8859-1"));
                } else {
                    self.codepage = Some(1200);
                }
            }
            Some(codepage) => {
                let name = match codepage {
                    1200 => "utf_16_le".to_string(),
                    10000 | 32768 => "mac_roman".to_string(),
                    10006 => "mac_greek".to_string(),
                    10007 => "mac_cyrillic".to_string(),
                    10029 => "mac_latin2".to_string(),
                    10079 => "mac_iceland".to_string(),
                    10081 => "mac_turkish".to_string(),
                    32769 => "cp1252".to_string(),
                    300..=1999 => format!("cp{codepage}"),
                    _ if self.biff_version >= 80 => {
                        self.codepage = Some(1200);
                        "utf_16_le".to_string()
                    }
                    _ => format!("unknown_codepage_{codepage}"),
                };
                self.encoding = Some(Encoding::named(&name));
            }
        }
        if self.codepage != Some(1200) {
            let enc = self.encoding.clone();
            let trial = enc.as_ref().map(|e| e.decode(b"trial"));
            if let Some(Err(e)) = trial {
                let cp = self.codepage.map_or("None".to_string(), |c| c.to_string());
                let en = enc.as_ref().map_or(String::new(), |x| ascii_str(&x.name));
                self.log.push_str(&format!(
                    "ERROR *** codepage {cp} -> encoding {en} -> {}: {}\n",
                    e.kind, e.message
                ));
                return Err(e);
            }
        }
        if self.raw_user_name {
            let name = self.user_name;
            unpack_string(name, 0, self.encoding.as_ref(), 1)?;
            self.raw_user_name = false;
        }
        Ok(())
    }

    /// `bk.encoding or bk.derive_encoding()`.
    pub(crate) fn encoding_or_derive(&mut self) -> R<Option<Encoding>> {
        if self.encoding.is_none() {
            self.derive_encoding()?;
        }
        Ok(self.encoding.clone())
    }

    pub(crate) fn handle_codepage(&mut self, data: &[u8]) -> R<()> {
        let b = need(slice(data, 0, 2), 2)?;
        self.codepage = Some(i64::from(u16_at(b, 0)));
        self.derive_encoding()
    }

    pub(crate) fn handle_country(&mut self, data: &[u8]) -> R<()> {
        let b = need(slice(data, 0, 4), 4)?;
        let c = (u16_at(b, 0), u16_at(b, 2));
        if !(self.countries == (0, 0) || self.countries == c) {
            return Err(assertion());
        }
        self.countries = c;
        Ok(())
    }

    pub(crate) fn handle_datemode(&mut self, data: &[u8]) -> R<()> {
        let b = need(slice(data, 0, 2), 2)?;
        if u16_at(b, 0) > 1 {
            return Err(assertion());
        }
        Ok(())
    }

    fn handle_externname(&mut self, data: &[u8]) -> R<()> {
        if self.biff_version >= 80 {
            need(slice(data, 0, 6), 6)?;
            let (name, _pos) = unpack_unicode_update_pos(data, 6, 1, None)?;
            let last = self.supbook_types.last().ok_or_else(list_index_error)?;
            if *last == Some(SUPBOOK_ADDIN) {
                self.addin_func_names.push(name);
            }
        }
        Ok(())
    }

    fn handle_externsheet(&mut self, data: &'a [u8]) -> R<()> {
        self.derive_encoding()?;
        self.extnsht_count += 1;
        if self.biff_version >= 80 {
            let num_refs = i64::from(u16_at(need(slice(data, 0, 2), 2)?, 0));
            let bytes_reqd = num_refs * 6 + 2;
            let mut joined: Vec<u8> = data.to_vec();
            while (joined.len() as i64) < bytes_reqd {
                let (code2, _len, data2) = self.get_record_parts()?;
                if code2 != XL_CONTINUE {
                    return Err(xlrd_err("Missing CONTINUE after EXTERNSHEET record"));
                }
                joined.extend_from_slice(data2);
            }
            let mut pos = 2;
            for _ in 0..num_refs {
                let b = need(span(&joined, pos, 6), 6)?;
                self.externsheet_info
                    .push((u16_at(b, 0), u16_at(b, 2), u16_at(b, 4)));
                pos += 6;
            }
        } else {
            let b = need(slice(data, 0, 2), 2)?;
            let (nc, mut ty) = (i64::from(u8_at(b, 0)), u8_at(b, 1));
            if ty == 3 {
                let enc = self.encoding.clone();
                let name = crate::py::decode_opt(slice(data, 2, nc + 2), enc.as_ref())?;
                self.extnsht_name_from_num.insert(self.extnsht_count, name);
            }
            if !(1..=4).contains(&ty) {
                ty = 0;
            }
            self.externsheet_type_b57.push(ty);
        }
        Ok(())
    }

    fn handle_name(&mut self, data: &'a [u8]) -> R<()> {
        let bv = self.biff_version;
        if bv < 50 {
            return Ok(());
        }
        self.derive_encoding()?;
        let h = need(slice(data, 0, 14), 14)?;
        let option_flags = u16_at(h, 0);
        let name_len = i64::from(u8_at(h, 3));
        let fmla_len = i64::from(u16_at(h, 4));
        let extsht_index = i64::from(u16_at(h, 6));
        let sheet_index = i64::from(u16_at(h, 8));
        let name_index = self.names.len() as i64;
        let (mut internal, pos) = if bv < 80 {
            unpack_string_update_pos(data, 14, self.encoding.as_ref(), 1, Some(name_len))?
        } else {
            unpack_unicode_update_pos(data, 14, 2, Some(name_len))?
        };
        if self.label_names.contains(&internal) {
            internal.push_str(&name_index.to_string());
        }
        self.label_names.insert(internal.clone());
        let builtin = (option_flags & 0x20) >> 5;
        let name = if builtin != 0 {
            let first = internal
                .chars()
                .next()
                .ok_or_else(|| err("IndexError", "string index out of range"))?;
            BUILTIN_NAME_FROM_CODE
                .get(first as usize)
                .map_or("??Unknown??", |v| v)
                .to_string()
        } else {
            internal
        };
        self.names.push(Name::new(
            name,
            option_flags,
            extsht_index,
            sheet_index,
            name_index,
            from(data, pos),
            fmla_len,
        ));
        Ok(())
    }

    fn names_epilogue(&mut self) -> R<IndexMap<String, Vec<usize>>> {
        let n = self.names.len();
        for namex in 0..n {
            let (excel_sheet_index, extn_sheet_num) = self
                .names
                .get(namex)
                .map(|o| (o.excel_sheet_index, o.extn_sheet_num))
                .ok_or_else(list_index_error)?;
            let intl = if self.biff_version >= 80 {
                if excel_sheet_index == 0 {
                    -1
                } else if 1 <= excel_sheet_index
                    && excel_sheet_index <= self.all_sheets_map.len() as i64
                {
                    match self.all_sheets_map.get((excel_sheet_index - 1) as usize) {
                        Some(-1) | None => -2,
                        Some(v) => *v,
                    }
                } else {
                    -3
                }
            } else if extn_sheet_num == 0 {
                -1
            } else {
                let name = self
                    .extnsht_name_from_num
                    .get(&extn_sheet_num)
                    .ok_or_else(|| err("KeyError", extn_sheet_num.to_string()))?;
                self.sheet_num_from_name.get(name).copied().unwrap_or(-2)
            };
            if let Some(o) = self.names.get_mut(namex) {
                o.scope = intl;
            }
        }
        for namex in 0..n {
            let (macro_, raw, binary, evaluated) = self
                .names
                .get(namex)
                .map(|o| (o.macro_ != 0, o.raw_formula, o.binary != 0, o.evaluated))
                .ok_or_else(list_index_error)?;
            if macro_ {
                self.dump_formula(raw, raw.len() as i64, self.biff_version, 0)?;
            }
            if binary || evaluated {
                continue;
            }
            self.evaluate_name_formula(namex, namex as i64, false, 0)?;
        }
        let mut map: IndexMap<String, Vec<(i64, usize)>> = IndexMap::new();
        for (namex, o) in self.names.iter().enumerate() {
            map.entry(o.name.to_lowercase())
                .or_default()
                .push((o.scope, namex));
        }
        Ok(map
            .into_iter()
            .map(|(k, mut v)| {
                v.sort_unstable();
                (k, v.into_iter().map(|(_, x)| x).collect())
            })
            .collect())
    }

    fn handle_supbook(&mut self, data: &[u8]) -> R<()> {
        self.supbook_types.push(None);
        let num_sheets = u16_at(need(slice(data, 0, 2), 2)?, 0);
        self.supbook_count += 1;
        if slice(data, 2, 4) == b"\x01\x04" {
            self.set_last_supbook(SUPBOOK_INTERNAL);
            self.supbook_locals_inx = Some(self.supbook_count - 1);
            return Ok(());
        }
        if slice(data, 0, 4) == b"\x01\x00\x01\x3A" {
            self.set_last_supbook(SUPBOOK_ADDIN);
            self.supbook_addins_inx = Some(self.supbook_count - 1);
            return Ok(());
        }
        let (_url, mut pos) = unpack_unicode_update_pos(data, 2, 2, None)?;
        if num_sheets == 0 {
            self.set_last_supbook(SUPBOOK_DDEOLE);
            return Ok(());
        }
        self.set_last_supbook(SUPBOOK_EXTERNAL);
        for _ in 0..num_sheets {
            match unpack_unicode_update_pos(data, pos, 2, None) {
                Ok((_shname, p)) => pos = p,
                Err(e) if e.kind == "error" => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn set_last_supbook(&mut self, v: u8) {
        if let Some(l) = self.supbook_types.last_mut() {
            *l = Some(v);
        }
    }

    fn handle_sheethdr(&mut self, data: &'a [u8]) -> R<()> {
        self.derive_encoding()?;
        let sheet_len = i64::from(i32_at(need(slice(data, 0, 4), 4)?, 0));
        let sheet_name = unpack_string(data, 4, self.encoding.as_ref(), 1)?;
        let sheetno = self.sheethdr_count as usize;
        let want = self.sheet_names.get(sheetno).ok_or_else(list_index_error)?;
        if &sheet_name != want {
            return Err(assertion());
        }
        self.sheethdr_count += 1;
        let bof_posn = self.position;
        self.initialise_format_info();
        self.sheet_list.push(None);
        self.get_sheet(sheetno, false)?;
        self.position = bof_posn + sheet_len;
        Ok(())
    }

    fn initialise_format_info(&mut self) {
        self.format_keys.clear();
        self.xfcount = 0;
        self.actualfmtcount = 0;
        self.xf_epilogue_done = false;
        self.xf_list.clear();
        self.font_list.clear();
    }

    fn handle_sst(&mut self, data: &'a [u8]) -> R<()> {
        let nstrings = i64::from(i32_at(need(slice(data, 4, 8), 4)?, 0));
        let mut strlist = vec![data];
        loop {
            let pos = self.position;
            let hdr = need(span(self.mem, pos, 4), 4)?;
            if u16_at(hdr, 0) != XL_CONTINUE {
                break;
            }
            let length = i64::from(u16_at(hdr, 2));
            strlist.push(span(self.mem, pos + 4, length));
            self.position = pos + 4 + length;
        }
        self.sharedstrings = self.unpack_sst_table(&strlist, nstrings)?;
        Ok(())
    }

    /// book.unpack_SST_table. Run lists aren't kept but their reads can raise.
    fn unpack_sst_table(&self, datatab: &[&[u8]], nstrings: i64) -> R<Vec<Arc<str>>> {
        let mut datainx = 0usize;
        let ndatas = datatab.len();
        let mut data: &[u8] = datatab.first().copied().unwrap_or(&[]);
        let mut datalen = data.len() as i64;
        let mut pos = 8i64;
        let mut strings: Vec<Arc<str>> = Vec::new();
        let mut text_total = 0usize;
        for i in 0..nstrings.max(0) {
            if i % 1024 == 0 {
                self.poll()?;
            }
            if strings.len() >= self.limits.max_strings {
                return Err(memory_error());
            }
            let nchars = i64::from(u16_at(need(span(data, pos, 2), 2)?, 0));
            pos += 2;
            let mut options = crate::py::byte_at(data, pos)?;
            pos += 1;
            let mut rtcount = 0i64;
            let mut phosz = 0i64;
            if options & 0x08 != 0 {
                rtcount = i64::from(u16_at(need(span(data, pos, 2), 2)?, 0));
                pos += 2;
            }
            if options & 0x04 != 0 {
                phosz = i64::from(i32_at(need(span(data, pos, 4), 4)?, 0));
                pos += 4;
            }
            let mut acc = String::new();
            let mut charsgot = 0i64;
            loop {
                let charsneed = nchars - charsgot;
                let charsavail;
                if options & 0x01 != 0 {
                    charsavail = ((datalen - pos) >> 1).min(charsneed);
                    acc.push_str(&crate::py::utf16le(span(data, pos, 2 * charsavail))?);
                    pos += 2 * charsavail;
                } else {
                    charsavail = (datalen - pos).min(charsneed);
                    acc.push_str(&crate::py::latin1(span(data, pos, charsavail)));
                    pos += charsavail;
                }
                charsgot += charsavail;
                if charsgot == nchars {
                    break;
                }
                datainx += 1;
                data = datatab.get(datainx).copied().ok_or_else(list_index_error)?;
                datalen = data.len() as i64;
                options = crate::py::byte_at(data, 0)?;
                pos = 1;
            }
            for _ in 0..rtcount {
                if pos == datalen {
                    pos = 0;
                    datainx += 1;
                    data = datatab.get(datainx).copied().ok_or_else(list_index_error)?;
                    datalen = data.len() as i64;
                }
                need(span(data, pos, 4), 4)?;
                pos += 4;
            }
            pos += phosz;
            if pos >= datalen {
                pos -= datalen;
                datainx += 1;
                if datainx < ndatas {
                    data = datatab.get(datainx).copied().unwrap_or(&[]);
                    datalen = data.len() as i64;
                } else if i != nstrings - 1 {
                    return Err(assertion());
                }
            }
            text_total += acc.len();
            if text_total > self.limits.max_text {
                return Err(memory_error());
            }
            strings.push(Arc::from(acc));
        }
        Ok(strings)
    }

    pub(crate) fn handle_writeaccess(&mut self, data: &'a [u8]) -> R<()> {
        if self.biff_version < 80 {
            if self.encoding.is_none() {
                self.raw_user_name = true;
                self.user_name = data;
                return Ok(());
            }
            unpack_string(data, 0, self.encoding.as_ref(), 1)?;
        } else if let Err(e) = unpack_unicode(data, 0, 2) {
            if e.kind != "UnicodeDecodeError" {
                return Err(e);
            }
            unpack_unicode(strip_ascii(data), 0, 2)?;
        }
        Ok(())
    }

    /// Book.parse_globals; returns name_map.
    fn parse_globals(&mut self) -> R<IndexMap<String, Vec<usize>>> {
        self.initialise_colour_map();
        self.xf_epilogue_done = false;
        loop {
            self.poll()?;
            let (rc, _length, data) = self.get_record_parts()?;
            match rc {
                0xfc => self.handle_sst(data)?,
                0x31 | 0x231 => self.handle_font(data)?,
                XL_FORMAT => self.handle_format(data, XL_FORMAT)?,
                0xe0 => self.handle_xf(data)?,
                0x85 => self.handle_boundsheet(data)?,
                0x22 => self.handle_datemode(data)?,
                0x42 => self.handle_codepage(data)?,
                0x8c => self.handle_country(data)?,
                0x23 => self.handle_externname(data)?,
                0x17 => self.handle_externsheet(data)?,
                0x2f => return Err(xlrd_err("Workbook is encrypted")),
                0x5c => self.handle_writeaccess(data)?,
                0x8e => {
                    self.sheetsoffset = Some(i64::from(i32_at(need(data, 4)?, 0)));
                }
                0x8f => self.handle_sheethdr(data)?,
                0x1ae => self.handle_supbook(data)?,
                0x18 => self.handle_name(data)?,
                0x92 => self.handle_palette(data)?,
                0x293 => self.handle_style(data)?,
                0x0a => {
                    self.xf_epilogue_done = true;
                    let map = self.names_epilogue()?;
                    if self.encoding.is_none() {
                        self.derive_encoding()?;
                    }
                    return Ok(map);
                }
                _ => {}
            }
        }
    }

    // === formatting.py ===

    fn initialise_colour_map(&mut self) {
        let ndpal = if self.biff_version >= 50 { 56 } else { 16 };
        // Keys 0..=ndpal+9, 0x51 and 0x7FFF; a PALETTE only overwrites existing ones.
        self.colour_keys_end = ndpal + 8 + 2;
    }

    fn colour_known(&self, k: i64) -> bool {
        (0..self.colour_keys_end).contains(&k) || k == 0x51 || k == 0x7FFF
    }

    pub(crate) fn handle_efont(&mut self, data: &[u8]) -> R<()> {
        let v = i64::from(u16_at(need(data, 2)?, 0));
        let f = self.font_list.last_mut().ok_or_else(list_index_error)?;
        f.colour_index = v;
        Ok(())
    }

    pub(crate) fn handle_font(&mut self, data: &[u8]) -> R<()> {
        if self.encoding.is_none() {
            self.derive_encoding()?;
        }
        let bv = self.biff_version;
        if self.font_list.len() == 4 {
            self.font_list.push(Font::default());
        }
        let mut f = Font::default();
        if bv >= 50 {
            let b = need(slice(data, 0, 13), 13)?;
            f.height = i64::from(u16_at(b, 0));
            f.colour_index = i64::from(u16_at(b, 4));
            if bv >= 80 {
                unpack_unicode(data, 14, 1)?;
            } else {
                unpack_string(data, 14, self.encoding.as_ref(), 1)?;
            }
        } else if bv >= 30 {
            let b = need(slice(data, 0, 6), 6)?;
            f.height = i64::from(u16_at(b, 0));
            f.colour_index = i64::from(u16_at(b, 4));
            unpack_string(data, 6, self.encoding.as_ref(), 1)?;
        } else {
            let b = need(slice(data, 0, 4), 4)?;
            f.height = i64::from(u16_at(b, 0));
            f.colour_index = 0x7FFF;
            unpack_string(data, 4, self.encoding.as_ref(), 1)?;
        }
        self.font_list.push(f);
        Ok(())
    }

    pub(crate) fn handle_format(&mut self, data: &[u8], rectype: u16) -> R<()> {
        let mut bv = self.biff_version;
        if rectype == XL_FORMAT2 {
            bv = bv.min(30);
        }
        if self.encoding.is_none() {
            self.derive_encoding()?;
        }
        let mut strpos = 2;
        let fmtkey;
        if bv >= 50 {
            fmtkey = i64::from(u16_at(need(slice(data, 0, 2), 2)?, 0));
        } else {
            fmtkey = self.actualfmtcount;
            if bv <= 30 {
                strpos = 0;
            }
        }
        self.actualfmtcount += 1;
        if bv >= 80 {
            unpack_unicode(data, 2, 2)?;
        } else {
            unpack_string(data, strpos, self.encoding.as_ref(), 1)?;
        }
        self.format_keys.insert(fmtkey);
        Ok(())
    }

    pub(crate) fn handle_palette(&mut self, data: &[u8]) -> R<()> {
        let n_colours = i64::from(u16_at(need(slice(data, 0, 2), 2)?, 0));
        let expected_size = 4 * n_colours + 2;
        let actual_size = data.len() as i64;
        if !(expected_size <= actual_size && actual_size <= expected_size + 4) {
            return Err(xlrd_err(format!(
                "PALETTE record: expected size {expected_size}, actual size {actual_size}"
            )));
        }
        if self.palette_loaded {
            return Err(assertion());
        }
        for i in 0..n_colours {
            if !self.colour_known(8 + i) {
                return Err(err("KeyError", (8 + i).to_string()));
            }
        }
        if n_colours > 0 {
            self.palette_loaded = true;
        }
        Ok(())
    }

    pub(crate) fn handle_style(&mut self, data: &[u8]) -> R<()> {
        let b = need(slice(data, 0, 4), 4)?;
        let flag_and_xfx = u16_at(b, 0);
        let mut built_in_id = i64::from(u8_at(b, 2));
        let mut level = i64::from(u8_at(b, 3));
        let mut xf_index = i64::from(flag_and_xfx & 0x0fff);
        let name;
        if data == b"\0\0\0\0" && self.normal_style.is_none() {
            xf_index = 0;
            name = "Normal".to_string();
        } else if flag_and_xfx & 0x8000 != 0 {
            let base = BUILT_IN_STYLE_NAMES
                .get(built_in_id as usize)
                .ok_or_else(list_index_error)?;
            let mut n = base.to_string();
            if (1..=2).contains(&built_in_id) {
                n.push_str(&(level + 1).to_string());
            }
            name = n;
        } else {
            built_in_id = 0;
            level = 0;
            if self.biff_version >= 80 {
                match unpack_unicode(data, 2, 2) {
                    Ok(n) => name = n,
                    Err(e) => {
                        if e.kind == "UnicodeDecodeError" {
                            self.log.push_str(&format!(
                                "STYLE: built_in=0 xf_index={xf_index} built_in_id={built_in_id} level={level}\n"
                            ));
                            self.log
                                .push_str(&format!("raw bytes: {}\n", repr_bytes(from(data, 2))));
                        }
                        return Err(e);
                    }
                }
            } else {
                name = unpack_string(data, 2, self.encoding.as_ref(), 1)?;
            }
        }
        if name == "Normal" {
            self.normal_style = Some(xf_index);
        }
        Ok(())
    }

    fn check_colour_indexes(&mut self, xf: &Xf, orig_index: i64) {
        let items = [
            (
                "XFBackground",
                "background_colour_index",
                xf.background_colour_index,
            ),
            (
                "XFBackground",
                "pattern_colour_index",
                xf.pattern_colour_index,
            ),
            ("XFBorder", "bottom_colour_index", xf.border_colours[0]),
            ("XFBorder", "diag_colour_index", xf.border_colours[1]),
            ("XFBorder", "left_colour_index", xf.border_colours[2]),
            ("XFBorder", "right_colour_index", xf.border_colours[3]),
            ("XFBorder", "top_colour_index", xf.border_colours[4]),
        ];
        for (oname, attr, v) in items {
            if !self.colour_known(v) {
                self.log.push_str(&format!(
                    "*** xf #{orig_index} : {oname}.{attr} =  0x{v:04x} (unknown)\n"
                ));
            }
        }
    }

    pub(crate) fn handle_xf(&mut self, data: &[u8]) -> R<()> {
        let bv = self.biff_version;
        let mut xf = Xf::default();
        if bv >= 50 && self.xfcount == 0 {
            for (lo, hi) in STD_FORMAT_RANGES {
                self.format_keys.extend(lo..=hi);
            }
        }
        // border_colours: bottom, diag, left, right, top.
        if bv >= 80 {
            let b = need(slice(data, 0, 20), 20)?;
            xf.font_index = i64::from(u16_at(b, 0));

            let align1 = i64::from(u8_at(b, 6));
            xf.hor_align = align1 & 0x07;
            xf.vert_align = (align1 & 0x70) >> 4;
            let brd1 = i64::from(u32_at(b, 10));
            let brd2 = i64::from(u32_at(b, 14));
            let brd3 = i64::from(u16_at(b, 18));
            xf.border_colours = [
                (brd2 & 0x3F80) >> 7,
                (brd2 & 0x1FC000) >> 14,
                (brd1 & 0x7f0000) >> 16,
                (brd1 & 0x3f80_0000) >> 23,
                brd2 & 0x7F,
            ];
            xf.pattern_colour_index = brd3 & 0x7F;
            xf.background_colour_index = (brd3 & 0x3F80) >> 7;
        } else if bv >= 50 {
            let b = need(slice(data, 0, 16), 16)?;
            xf.font_index = i64::from(u16_at(b, 0));

            let align1 = i64::from(u8_at(b, 6));
            xf.hor_align = align1 & 0x07;
            xf.vert_align = (align1 & 0x70) >> 4;
            let brd1 = i64::from(u32_at(b, 8));
            let brd2 = i64::from(u32_at(b, 12));
            xf.pattern_colour_index = brd1 & 0x7F;
            xf.background_colour_index = (brd1 & 0x3F80) >> 7;
            xf.border_colours = [
                (brd1 & 0xFE00_0000) >> 25,
                0,
                (brd2 & 0x7F0000) >> 16,
                (brd2 & 0x3F80_0000) >> 23,
                (brd2 & 0xFE00) >> 9,
            ];
        } else if bv >= 40 {
            let b = need(slice(data, 0, 12), 12)?;
            xf.font_index = i64::from(u8_at(b, 0));

            let align = i64::from(u8_at(b, 4));
            xf.hor_align = align & 0x07;
            xf.vert_align = (align & 0x30) >> 4;
            Self::xf_colours_34(&mut xf, b);
        } else if bv == 30 {
            let b = need(slice(data, 0, 12), 12)?;
            xf.font_index = i64::from(u8_at(b, 0));

            let align_par = i64::from(u16_at(b, 4));
            xf.hor_align = align_par & 0x07;
            xf.vert_align = 2;
            Self::xf_colours_34(&mut xf, b);
        } else if bv == 21 {
            let b = need(data, 4)?;
            xf.font_index = i64::from(u8_at(b, 0));
            let halign = i64::from(u8_at(b, 3));
            xf.hor_align = halign & 0x07;
            let side = |m: i64| if halign & m != 0 { 8 } else { 0 };
            xf.border_colours = [side(0x40), 0, side(0x08), side(0x10), side(0x20)];
            xf.background_colour_index = 9;
            xf.pattern_colour_index = 8;
            xf.vert_align = 2;
        } else {
            return Err(xlrd_err(format!("programmer stuff-up: bv={bv}")));
        }
        let index = self.xf_list.len() as i64;
        self.xf_list.push(xf.clone());
        self.xfcount += 1;
        self.check_colour_indexes(&xf, index);
        Ok(())
    }

    fn xf_colours_34(xf: &mut Xf, b: &[u8]) {
        let bkg = i64::from(u16_at(b, 6));
        let brd = i64::from(u32_at(b, 8));
        xf.pattern_colour_index = (bkg & 0x07C0) >> 6;
        xf.background_colour_index = (bkg & 0xF800) >> 11;
        xf.border_colours = [
            (brd & 0x00F8_0000) >> 19,
            0,
            (brd & 0xF800) >> 11,
            (brd & 0xF800_0000) >> 27,
            (brd & 0xF8) >> 3,
        ];
    }

    /// The key is in _xf_index_to_xl_type_map: 0, or any XF so far.
    pub(crate) fn xf_type_known(&self, xf_index: i64) -> bool {
        xf_index == 0 || (0 <= xf_index && xf_index < self.xf_list.len() as i64)
    }
}

fn strip_ascii(d: &[u8]) -> &[u8] {
    let ws = |b: &u8| matches!(*b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    let start = d.iter().position(|b| !ws(b)).unwrap_or(d.len());
    let end = d.iter().rposition(|b| !ws(b)).map_or(start, |p| p + 1);
    d.get(start..end).unwrap_or(&[])
}

/// xlrd2.open_workbook(.., formatting_info=True) for anything not a ZIP.
pub(crate) fn open_xls(
    data: &[u8],
    log: &mut String,
    expired: &dyn Fn() -> bool,
    limits: Limits,
) -> Result<LoadedOwned, XlError> {
    if data.is_empty() {
        return Err(xlrd_err("File size is 0 bytes"));
    }
    if data.len() > limits.max_stream {
        return Err(memory_error());
    }
    let mut joined: Vec<u8> = Vec::new();
    let mut base = 0i64;
    let mut use_joined = false;
    if slice(data, 0, 8) == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" {
        let mut cd = CompDoc::new(data, log, expired)?;
        let mut found = false;
        for qname in ["Workbook", "Book"] {
            match cd.locate_named_stream(qname, log, expired)? {
                Located::NotFound => {}
                Located::InFile { base: b } => {
                    base = b;
                    found = true;
                }
                Located::Joined(v) => {
                    use_joined = true;
                    found = !v.is_empty();
                    joined = v;
                }
            }
            if found {
                break;
            }
        }
        if !found {
            return Err(xlrd_err("Can't find workbook in OLE2 compound document"));
        }
    }
    let mem: &[u8] = if use_joined { &joined } else { data };
    let mut bk = Loader::new(mem, log, expired);
    bk.limits = limits;
    bk.base = base;
    bk.position = base;
    let (biff_version, _stream) = bk.getbof(XL_WORKBOOK_GLOBALS)?;
    if biff_version == 0 {
        return Err(xlrd_err("Can't determine file's BIFF version"));
    }
    bk.biff_version = biff_version;
    let mut name_map = IndexMap::new();
    if biff_version <= 40 {
        bk.fake_globals_get_sheet()?;
    } else if biff_version == 45 {
        name_map = bk.parse_globals()?;
    } else {
        name_map = bk.parse_globals()?;
        bk.sheet_list = bk.sheet_names.iter().map(|_| None).collect();
        bk.get_sheets()?;
    }
    let nsheets = bk.sheet_list.len();
    if biff_version == 45 && nsheets > 1 {
        bk.log.push_str(&format!(
            "*** WARNING: Excel 4.0 workbook (.XLW) file contains {nsheets} worksheets.\n*** Book-level data will be that of the last worksheet.\n"
        ));
    }
    let names = bk
        .names
        .iter()
        .map(|n| crate::NameResult {
            result: n.result().cloned(),
        })
        .collect();
    Ok(LoadedOwned {
        sheet_list: bk.sheet_list,
        sheet_names: bk.sheet_names,
        names,
        name_map,
        xf_list: bk.xf_list,
        font_list: bk.font_list,
        normal_style: bk.normal_style,
        nsheets,
    })
}

/// What Book::open keeps.
pub(crate) struct LoadedOwned {
    pub(crate) sheet_list: Vec<Option<Sheet>>,
    pub(crate) sheet_names: Vec<String>,
    pub(crate) names: Vec<crate::NameResult>,
    pub(crate) name_map: IndexMap<String, Vec<usize>>,
    pub(crate) xf_list: Vec<Xf>,
    pub(crate) font_list: Vec<Font>,
    pub(crate) normal_style: Option<i64>,
    pub(crate) nsheets: usize,
}

/// zipfile plus open_workbook's dispatch: every path raises.
pub(crate) fn zip_refusal(data: &[u8]) -> XlError {
    let bad = |m: &str| err("BadZipFile", m);
    let n = data.len() as i64;
    let tail = slice(data, (n - 22).max(0), n);
    let eocd = if tail.len() == 22 && tail.starts_with(b"PK\x05\x06") && tail.ends_with(b"\0\0") {
        Some((n - 22) as usize)
    } else {
        let start = (n - 65557).max(0) as usize;
        data.get(start..)
            .and_then(|w| w.windows(4).rposition(|x| x == b"PK\x05\x06"))
            .map(|p| start + p)
    };
    let Some(eocd) = eocd else {
        return bad("File is not a zip file");
    };
    let rec = span(data, eocd as i64, 22);
    if rec.len() < 22 {
        return bad("File is not a zip file");
    }
    let size_cd = i64::from(u32_at(rec, 12));
    let offset_cd = i64::from(u32_at(rec, 16));
    let concat = eocd as i64 - size_cd - offset_cd;
    if concat < 0 {
        return bad("Bad offset for central directory");
    }
    let dir = span(data, offset_cd + concat, size_cd);
    let mut pos = 0i64;
    let mut names: Vec<String> = Vec::new();
    while pos < dir.len() as i64 {
        let h = span(dir, pos, 46);
        if h.len() < 46 {
            return bad("Truncated central directory");
        }
        if !h.starts_with(b"PK\x01\x02") {
            return bad("Bad magic number for central directory");
        }
        let nl = i64::from(u16_at(h, 28));
        let el = i64::from(u16_at(h, 30));
        let cl = i64::from(u16_at(h, 32));
        let raw = span(dir, pos + 46, nl);
        names.push(
            String::from_utf8_lossy(raw)
                .replace('\\', "/")
                .to_lowercase(),
        );
        pos += 46 + nl + el + cl;
    }
    let has = |w: &str| names.iter().any(|x| x == w);
    if has("xl/workbook.xml") {
        err(
            "NotImplementedError",
            "formatting_info=True not yet implemented",
        )
    } else if has("xl/workbook.bin") {
        xlrd_err("Excel 2007 xlsb file; not supported")
    } else if has("content.xml") {
        xlrd_err("Openoffice.org ODS file; not supported")
    } else {
        xlrd_err("ZIP file contents not a known type of workbook")
    }
}
