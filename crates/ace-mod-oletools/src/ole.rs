//! olefile 0.47's `OleFileIO`, for reading. It isn't on the cfb crate, whatever PLAN.md 4.10 says:
//! olefile opens containers cfb refuses, keeps going past defects, and exposes orphaned directory
//! entries, and olevba's results depend on each of those (docs/measurements/oletools-hostile.md).
//!
//! olefile's only fatal defects are the ones raising here. Everything it records in `parsing_issues`
//! changes nothing that's read, so it isn't recorded. Python's arithmetic is unbounded and a sector
//! shift can be 65535, so sizes are u128, saturated at a shift no seek can survive.

use std::sync::Arc;

use crate::py::{PyErr, PyResult, decode_utf16le, memory_error};

pub const MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const FREESECT: u32 = 0xFFFF_FFFF;
const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
const NOSTREAM: u32 = 0xFFFF_FFFF;
pub const STGTY_STORAGE: u8 = 1;
pub const STGTY_STREAM: u8 = 2;
const UNKNOWN_SIZE: u64 = 0x7FFF_FFFF;
const MINIMAL_OLEFILE_SIZE: usize = 1536;
/// Where olefile's `seek` stops being possible: BytesIO and a file both take a C long.
const SEEK_MAX: u128 = i64::MAX as u128;
/// The most one stream may read. olefile reads what a FAT loop and a declared size say, up to
/// memory, and this is that memory: past it a read raises MemoryError, as Python would.
pub const MAX_STREAM: usize = 256 * 1024 * 1024;

/// Python's limit on nested calls, as the frames the port's recursive functions cost.
const RECURSION_LIMIT: usize = 1000;
const LOADING_FRAMES: usize = 6;

fn fatal(message: &str) -> PyErr {
    PyErr::new("OleFileError", message)
}

/// `olefile.isOleFile` of a file-like object: only the magic.
pub fn has_magic(data: &[u8]) -> bool {
    data.len() >= 8 && data[..8] == MAGIC
}

/// One directory entry. Only what the ported code reads.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub sid: usize,
    pub name: String,
    lower: String,
    pub entry_type: u8,
    sid_left: u32,
    sid_right: u32,
    sid_child: u32,
    pub clsid: String,
    pub start: u32,
    pub size: u64,
    kids: Vec<usize>,
    used: bool,
}

#[derive(Debug)]
pub struct OleFile {
    data: Arc<Vec<u8>>,
    sector_size: u128,
    mini_sector_size: u128,
    num_mini_fat_sectors: u32,
    first_mini_fat_sector: u32,
    fat: Vec<u32>,
    minifat: Option<Vec<u32>>,
    ministream: Option<Vec<u8>>,
    directory: Vec<u8>,
    pub direntries: Vec<Option<DirEntry>>,
}

fn u16_at(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// olefile's `_clsid`.
fn clsid_text(raw: &[u8]) -> String {
    if raw.iter().all(|&byte| byte == 0) {
        return String::new();
    }
    let mut out = format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-",
        u32_at(raw, 0),
        u16_at(raw, 4),
        u16_at(raw, 6),
        raw[8],
        raw[9]
    );
    for byte in &raw[10..16] {
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

fn sect2array(data: &[u8]) -> PyResult<Vec<u32>> {
    if !data.len().is_multiple_of(4) {
        return Err(PyErr::new(
            "ValueError",
            "bytes length not a multiple of item size",
        ));
    }
    Ok(data
        .as_chunks::<4>()
        .0
        .iter()
        .map(|four| u32_at(four, 0))
        .collect())
}

/// Reads what the arguments of `OleStream.__init__` say. Every defect it has is non-fatal: a broken
/// chain ends the read and a short stream is short.
fn read_chain(
    source: &[u8],
    start: u32,
    size: u64,
    offset: u128,
    sector_size: u128,
    fat: &[u32],
) -> PyResult<Vec<u8>> {
    let unknown = size == UNKNOWN_SIZE;
    let size: u128 = if unknown {
        fat.len() as u128 * sector_size
    } else {
        u128::from(size)
    };
    let sectors = size.div_ceil(sector_size);
    let mut data = Vec::new();
    let mut sect = start;
    let mut index: u128 = 0;
    while index < sectors {
        index += 1;
        if sect == ENDOFCHAIN && unknown {
            break;
        }
        // includes ENDOFCHAIN on a stream with a known size, after a defect it doesn't raise
        if sect as usize >= fat.len() {
            break;
        }
        let at = offset + sector_size * u128::from(sect);
        if at > SEEK_MAX {
            break;
        }
        // reading past the end gives nothing, and a short sector is kept
        if at < source.len() as u128 {
            let from = at as usize;
            let to = (at + sector_size).min(source.len() as u128) as usize;
            if data.len() + (to - from) > MAX_STREAM {
                return Err(memory_error());
            }
            data.extend_from_slice(&source[from..to]);
        }
        sect = fat[sect as usize];
    }
    if data.len() as u128 >= size {
        data.truncate(size as usize);
    }
    Ok(data)
}

impl OleFile {
    /// `OleFileIO(file)`, on a path or a file-like object. `depth` is the Python frames already on
    /// the stack, which decides where a crafted directory hits RecursionError.
    pub fn open(data: Arc<Vec<u8>>, depth: usize) -> PyResult<OleFile> {
        if data.len() < 512 || !has_magic(&data) {
            return Err(PyErr::new(
                "NotOleFileError",
                "not an OLE2 structured storage file",
            ));
        }
        let header: Vec<u8> = data[..512].to_vec();
        let header = &header[..];
        let sector_shift = u16_at(header, 30);
        let mini_shift = u16_at(header, 32);
        // past these no seek works, so the exact value no longer matters
        let sector_size = 1u128 << sector_shift.min(120);
        let mini_sector_size = 1u128 << mini_shift.min(120);
        let filesize = data.len() as u128;
        let nb_sect = filesize.div_ceil(sector_size).saturating_sub(1);
        let mut ole = OleFile {
            data,
            sector_size,
            mini_sector_size,
            num_mini_fat_sectors: u32_at(header, 64),
            first_mini_fat_sector: u32_at(header, 60),
            fat: Vec::new(),
            minifat: None,
            ministream: None,
            directory: Vec::new(),
            direntries: Vec::new(),
        };
        ole.loadfat(header, nb_sect)?;
        ole.loaddirectory(u32_at(header, 48), depth)?;
        Ok(ole)
    }

    /// `OleFileIO(bytes)`: under 1536 bytes olefile takes bytes for a path, and that path doesn't
    /// exist or holds a NUL, and both raise.
    pub fn open_bytes(data: Arc<Vec<u8>>, depth: usize) -> PyResult<OleFile> {
        if data.len() < MINIMAL_OLEFILE_SIZE {
            return Err(PyErr::new("FileNotFoundError", "not a file"));
        }
        OleFile::open(data, depth)
    }

    fn getsect(&self, sect: u32) -> PyResult<&[u8]> {
        let at = self.sector_size * (u128::from(sect) + 1);
        if at > SEEK_MAX {
            return Err(fatal("OLE sector index out of range"));
        }
        let end = at + self.sector_size;
        if end > self.data.len() as u128 {
            return Err(fatal("incomplete OLE sector"));
        }
        Ok(&self.data[at as usize..end as usize])
    }

    /// `loadfat_sect`. It keeps no more than olefile's final FAT would, so a DIFAT that repeats one
    /// sector can't take memory, and it still reads each sector, for what a bad one raises.
    fn loadfat_sect(&mut self, entries: &[u32], keep: u128) -> PyResult<()> {
        for &isect in entries {
            if isect == ENDOFCHAIN || isect == FREESECT {
                break;
            }
            let sector = self.getsect(isect)?;
            if sector.len() % 4 != 0 {
                sect2array(sector)?;
            }
            if (self.fat.len() as u128) < keep {
                let next = sect2array(self.getsect(isect)?)?;
                self.fat.extend_from_slice(&next);
            }
        }
        Ok(())
    }

    fn loadfat(&mut self, header: &[u8], nb_sect: u128) -> PyResult<()> {
        let first = sect2array(&header[76..512])?;
        self.loadfat_sect(&first, nb_sect)?;
        let num_difat = u32_at(header, 72);
        let num_fat = u32_at(header, 44);
        let first_difat = u32_at(header, 68);
        if num_difat != 0 {
            if u128::from(first_difat) >= nb_sect {
                return Err(fatal("incorrect DIFAT, first index out of range"));
            }
            let per_sector = (self.sector_size / 4) as i128 - 1;
            if per_sector == 0 {
                return Err(PyErr::new("ZeroDivisionError", "division by zero"));
            }
            let nb_difat = (i128::from(num_fat) - 109 + per_sector - 1).div_euclid(per_sector);
            if i128::from(num_difat) != nb_difat {
                return Err(PyErr::new("OSError", "incorrect DIFAT"));
            }
            let mut isect = first_difat;
            for _ in 0..nb_difat {
                let difat = sect2array(self.getsect(isect)?)?;
                let split = if per_sector < 0 {
                    difat.len().saturating_sub(1)
                } else {
                    per_sector as usize
                };
                self.loadfat_sect(&difat[..split.min(difat.len())], nb_sect)?;
                isect = *difat
                    .get(split)
                    .ok_or_else(|| PyErr::new("IndexError", "array index out of range"))?;
            }
            if isect != ENDOFCHAIN && isect != FREESECT {
                return Err(PyErr::new("OSError", "incorrect end of DIFAT"));
            }
        }
        if self.fat.len() as u128 > nb_sect {
            self.fat.truncate(nb_sect as usize);
        }
        Ok(())
    }

    fn loaddirectory(&mut self, sect: u32, depth: usize) -> PyResult<()> {
        self.directory = read_chain(
            &self.data,
            sect,
            UNKNOWN_SIZE,
            self.sector_size,
            self.sector_size,
            &self.fat,
        )?;
        let max_entries = self.directory.len() / 128;
        self.direntries = vec![None; max_entries];
        self.load_direntry(0)?;
        // OleFileIO.__init__, open, loaddirectory, then build_storage_tree
        self.build_storage_tree(0, depth + 3)
    }

    /// `_load_direntry`: an entry already loaded comes back, which olefile only records as a defect.
    fn load_direntry(&mut self, sid: usize) -> PyResult<()> {
        if sid >= self.direntries.len() {
            return Err(fatal("OLE directory index out of range"));
        }
        if self.direntries[sid].is_none() {
            let raw = &self.directory[sid * 128..sid * 128 + 128];
            self.direntries[sid] = Some(self.parse_entry(raw, sid));
        }
        Ok(())
    }

    fn parse_entry(&self, raw: &[u8], sid: usize) -> DirEntry {
        let mut name_length = i64::from(u16_at(raw, 64));
        if name_length > 64 {
            name_length = 64;
        }
        // a slice of name_length-2, which for 0 and 1 counts back from the end
        let keep = if name_length >= 2 {
            (name_length - 2) as usize
        } else {
            (64 + name_length - 2) as usize
        };
        let name = decode_utf16le(&raw[..keep]);
        let size_low = u32_at(raw, 120);
        let size_high = u32_at(raw, 124);
        let size = if self.sector_size == 512 {
            u64::from(size_low)
        } else {
            u64::from(size_low) + (u64::from(size_high) << 32)
        };
        DirEntry {
            sid,
            lower: name.to_lowercase(),
            name,
            entry_type: raw[66],
            sid_left: u32_at(raw, 68),
            sid_right: u32_at(raw, 72),
            sid_child: u32_at(raw, 76),
            clsid: clsid_text(&raw[80..96]),
            start: u32_at(raw, 116),
            size,
            kids: Vec::new(),
            used: false,
        }
    }

    fn entry(&self, sid: usize) -> &DirEntry {
        self.direntries[sid].as_ref().expect("a loaded entry")
    }

    fn build_storage_tree(&mut self, sid: usize, depth: usize) -> PyResult<()> {
        if depth >= RECURSION_LIMIT {
            return Err(recursion_error());
        }
        let child = self.entry(sid).sid_child;
        if child != NOSTREAM {
            self.append_kids(sid, child, depth + 1)?;
            let mut kids = std::mem::take(&mut self.direntries[sid].as_mut().expect("loaded").kids);
            // stable, by name, as olefile's list.sort on __lt__
            kids.sort_by(|&a, &b| self.entry(a).name.cmp(&self.entry(b).name));
            self.direntries[sid].as_mut().expect("loaded").kids = kids;
        }
        Ok(())
    }

    fn append_kids(&mut self, parent: usize, child_sid: u32, depth: usize) -> PyResult<()> {
        if depth >= RECURSION_LIMIT {
            return Err(recursion_error());
        }
        if child_sid == NOSTREAM || child_sid as usize >= self.direntries.len() {
            return Ok(());
        }
        let child = child_sid as usize;
        // loading an entry goes through _load_direntry and its constructor to logging, which is
        // where Python meets its limit first
        if depth + LOADING_FRAMES >= RECURSION_LIMIT {
            return Err(recursion_error());
        }
        self.load_direntry(child)?;
        if self.entry(child).used {
            return Ok(());
        }
        self.direntries[child].as_mut().expect("loaded").used = true;
        let (left, right) = (self.entry(child).sid_left, self.entry(child).sid_right);
        self.append_kids(parent, left, depth + 1)?;
        self.direntries[parent]
            .as_mut()
            .expect("loaded")
            .kids
            .push(child);
        self.append_kids(parent, right, depth + 1)?;
        self.build_storage_tree(child, depth + 1)
    }

    /// `root.clsid`.
    pub fn root_clsid(&self) -> &str {
        &self.entry(0).clsid
    }

    fn list(
        &self,
        files: &mut Vec<Vec<String>>,
        prefix: &[String],
        sid: usize,
        streams: bool,
        storages: bool,
    ) {
        for &kid in &self.entry(sid).kids {
            let entry = self.entry(kid);
            let path = || {
                let mut path = prefix.to_vec();
                path.push(entry.name.clone());
                path
            };
            if entry.entry_type == STGTY_STORAGE {
                if storages {
                    files.push(path());
                }
                self.list(files, &path(), kid, streams, storages);
            } else if entry.entry_type == STGTY_STREAM && streams {
                files.push(path());
            }
        }
    }

    /// `listdir(streams, storages)`.
    pub fn listdir(&self, streams: bool, storages: bool) -> Vec<Vec<String>> {
        let mut files = Vec::new();
        self.list(&mut files, &[], 0, streams, storages);
        files
    }

    /// `_find`, on a list of names. Case-insensitive, first match. An IOError when absent.
    pub fn find_parts<S: AsRef<str>>(&self, path: &[S]) -> PyResult<usize> {
        let mut node = 0;
        for name in path {
            let lower = name.as_ref().to_lowercase();
            let kid = self
                .entry(node)
                .kids
                .iter()
                .find(|&&kid| self.entry(kid).lower == lower);
            match kid {
                Some(&kid) => node = kid,
                None => return Err(PyErr::new("OSError", "file not found")),
            }
        }
        Ok(node)
    }

    /// `_find`, on a path with slashes.
    pub fn find(&self, path: &str) -> PyResult<usize> {
        let parts: Vec<&str> = path.split('/').collect();
        self.find_parts(&parts)
    }

    /// `exists`.
    pub fn exists(&self, path: &str) -> bool {
        self.find(path).is_ok()
    }

    /// `get_type`: `None` where olefile says False.
    pub fn get_type(&self, path: &str) -> Option<u8> {
        self.find(path).ok().map(|sid| self.entry(sid).entry_type)
    }

    /// `get_type` on a list of names.
    pub fn get_type_parts(&self, path: &[String]) -> Option<u8> {
        self.find_parts(path)
            .ok()
            .map(|sid| self.entry(sid).entry_type)
    }

    /// `openstream(path).read()`.
    pub fn read_stream(&mut self, path: &str) -> PyResult<Vec<u8>> {
        let parts: Vec<&str> = path.split('/').collect();
        self.read_stream_parts(&parts)
    }

    /// `openstream(path).read()`, on a list of names.
    pub fn read_stream_parts<S: AsRef<str>>(&mut self, path: &[S]) -> PyResult<Vec<u8>> {
        let sid = self.find_parts(path)?;
        let entry = self.entry(sid);
        if entry.entry_type != STGTY_STREAM {
            return Err(PyErr::new("OSError", "this file is not a stream"));
        }
        let (start, size) = (entry.start, entry.size);
        self.open_chain(start, size)
    }

    /// Loads an orphaned or unused entry, as `detect_vba_macros` does for every SID.
    pub fn load_entry(&mut self, sid: usize) -> PyResult<(u8, String, u32, u64)> {
        self.load_direntry(sid)?;
        let entry = self.entry(sid);
        Ok((
            entry.entry_type,
            entry.name.clone(),
            entry.start,
            entry.size,
        ))
    }

    /// `_open(start, size).read()`.
    pub fn open_chain(&mut self, start: u32, size: u64) -> PyResult<Vec<u8>> {
        if size < 0x1000 {
            self.ensure_ministream()?;
            read_chain(
                self.ministream.as_deref().unwrap_or_default(),
                start,
                size,
                0,
                self.mini_sector_size,
                self.minifat.as_deref().unwrap_or_default(),
            )
        } else {
            read_chain(
                &self.data,
                start,
                size,
                self.sector_size,
                self.sector_size,
                &self.fat,
            )
        }
    }

    fn ensure_ministream(&mut self) -> PyResult<()> {
        if self.ministream.is_some() {
            return Ok(());
        }
        let root_size = self.entry(0).size;
        let root_start = self.entry(0).start;
        let stream_size = u128::from(self.num_mini_fat_sectors) * self.sector_size;
        let minisectors = u128::from(root_size).div_ceil(self.mini_sector_size);
        let raw = read_chain(
            &self.data,
            self.first_mini_fat_sector,
            u64::try_from(stream_size).unwrap_or(u64::MAX),
            self.sector_size,
            self.sector_size,
            &self.fat,
        )?;
        let mut minifat = sect2array(&raw)?;
        if (minifat.len() as u128) > minisectors {
            minifat.truncate(minisectors as usize);
        }
        self.minifat = Some(minifat);
        self.ministream = Some(read_chain(
            &self.data,
            root_start,
            root_size,
            self.sector_size,
            self.sector_size,
            &self.fat,
        )?);
        Ok(())
    }
}

fn recursion_error() -> PyErr {
    PyErr::new("RecursionError", "maximum recursion depth exceeded")
}
