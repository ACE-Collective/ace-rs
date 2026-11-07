//! Python 3.14's `zipfile`, for reading, as far as oletools calls it: `is_zipfile`, the constructor,
//! `namelist`, `getinfo`, `open` then `read`, and `read`. Which exception a hostile member raises,
//! and whether `read(8)` sees it, depends on how much Python decompresses at a time, so the member
//! reader follows `ZipExtFile` call by call, and deflate and LZMA are ports of zlib 1.3.1's and
//! liblzma 5.8's decoders, which keep their error texts and the point where each error shows.
//! Method 93, zstd, which Python 3.14 reads, isn't here: it raises NotImplementedError.

use std::collections::HashMap;

use crate::codepage::Decoder;
use crate::py::{PyErr, PyResult, memory_error, repr_bytes, repr_str};

/// A read past this raises `memory_error()`, which Python would at some point.
pub const MAX_MEMBER: usize = 256 * 1024 * 1024;

const STRING_END: &[u8; 4] = b"PK\x05\x06";
const STRING_CENTRAL: &[u8; 4] = b"PK\x01\x02";
const STRING_FILE: &[u8; 4] = b"PK\x03\x04";
const STRING_END64: &[u8; 4] = b"PK\x06\x06";
const STRING_LOCATOR64: &[u8; 4] = b"PK\x06\x07";
const SIZE_END: usize = 22;
const SIZE_CENTRAL: usize = 46;
const SIZE_FILE: usize = 30;
const SIZE_END64: usize = 56;
const SIZE_LOCATOR64: usize = 20;
const MAX_COMMENT: usize = 65535;
const MAX_EXTRACT_VERSION: u8 = 63;

const FLAG_ENCRYPTED: u16 = 1;
const FLAG_PATCH: u16 = 1 << 5;
const FLAG_STRONG: u16 = 1 << 6;
const FLAG_UTF8: u16 = 1 << 11;

const STORED: u16 = 0;
const DEFLATED: u16 = 8;
const BZIP2: u16 = 12;
const LZMA: u16 = 14;
const ZSTANDARD: u16 = 93;

const MAX_N: usize = (1 << 31) - 1;
const MIN_READ_SIZE: usize = 4096;

fn bad_zip(message: impl Into<String>) -> PyErr {
    PyErr::new("BadZipFile", message)
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from(u32_at(bytes, at)) | u64::from(u32_at(bytes, at + 4)) << 32
}

/// `BytesIO.read(size)` at a position that may be anywhere at or after the start.
fn slice_at(data: &[u8], at: i128, size: usize) -> &[u8] {
    let len = data.len() as i128;
    if at >= len {
        return &[];
    }
    let start = at.max(0) as usize;
    &data[start..start.saturating_add(size).min(data.len())]
}

/// What `BytesIO.seek(pos)` raises.
fn check_seek(at: i128) -> PyResult<()> {
    if at > i128::from(i64::MAX) || at < i128::from(i64::MIN) {
        return Err(PyErr::new(
            "OverflowError",
            "Python int too large to convert to C ssize_t",
        ));
    }
    if at < 0 {
        return Err(PyErr::new(
            "ValueError",
            format!("negative seek value {at}"),
        ));
    }
    Ok(())
}

/// `bytes.decode('utf-8')`.
fn decode_utf8(bytes: &[u8]) -> PyResult<String> {
    match std::str::from_utf8(bytes) {
        Ok(text) => Ok(text.to_owned()),
        Err(error) => {
            let start = error.valid_up_to();
            let (end, reason) = match error.error_len() {
                None => (bytes.len(), "unexpected end of data"),
                Some(len) => {
                    let reason = if matches!(bytes[start], 0x80..=0xC1 | 0xF5..=0xFF) {
                        "invalid start byte"
                    } else {
                        "invalid continuation byte"
                    };
                    (start + len, reason)
                }
            };
            let message = if end - start == 1 {
                format!(
                    "'utf-8' codec can't decode byte 0x{:02x} in position {start}: {reason}",
                    bytes[start]
                )
            } else {
                format!(
                    "'utf-8' codec can't decode bytes in position {start}-{}: {reason}",
                    end - 1
                )
            };
            Err(PyErr::new("UnicodeDecodeError", message))
        }
    }
}

fn decode_name(bytes: &[u8], flags: u16) -> PyResult<String> {
    if flags & FLAG_UTF8 != 0 {
        decode_utf8(bytes)
    } else {
        Ok(Decoder::for_codepage(437).decode(bytes))
    }
}

/// `_sanitize_filename`, where `os.sep` is `/`.
fn sanitize(name: &str) -> String {
    match name.find('\0') {
        Some(at) => name[..at].to_owned(),
        None => name.to_owned(),
    }
}

struct EndRecord {
    disk_number: u64,
    disk_start: u64,
    entries_total: u64,
    size: u64,
    offset: u64,
    location: i128,
}

/// `_EndRecData64`: `offset` is where the end record is.
fn end_record64(data: &[u8], offset: i128, mut record: EndRecord) -> PyResult<EndRecord> {
    let mut offset = offset - SIZE_LOCATOR64 as i128;
    if offset < 0 {
        return Ok(record);
    }
    let locator = slice_at(data, offset, SIZE_LOCATOR64);
    if locator.len() != SIZE_LOCATOR64 {
        return Err(PyErr::new("OSError", "Unknown I/O error"));
    }
    if &locator[0..4] != STRING_LOCATOR64 {
        return Ok(record);
    }
    let disk_number = u32_at(locator, 4);
    let relative = i128::from(u64_at(locator, 8));
    let disks = u32_at(locator, 16);
    if disk_number != 0 || disks > 1 {
        return Err(bad_zip(
            "zipfiles that span multiple disks are not supported",
        ));
    }
    offset -= SIZE_END64 as i128;
    if relative > offset {
        return Err(bad_zip("Corrupt zip64 end of central directory locator"));
    }
    let mut extra = offset - relative;
    let mut end64 = slice_at(data, relative, SIZE_END64);
    if end64.len() != SIZE_END64 {
        return Err(PyErr::new("OSError", "Unknown I/O error"));
    }
    if &end64[0..4] != STRING_END64 && relative != offset {
        extra = 0;
        end64 = slice_at(data, offset, SIZE_END64);
        if end64.len() != SIZE_END64 {
            return Err(PyErr::new("OSError", "Unknown I/O error"));
        }
    }
    if &end64[0..4] != STRING_END64 {
        return Err(bad_zip("Zip64 end of central directory record not found"));
    }
    let record_size = i128::from(u64_at(end64, 4));
    let dir_size = u64_at(end64, 40);
    let dir_offset = u64_at(end64, 48);
    if i128::from(dir_offset) + i128::from(dir_size) != relative
        || record_size + 12 != SIZE_END64 as i128 + extra
    {
        return Err(bad_zip("Corrupt zip64 end of central directory record"));
    }
    record.disk_number = u64::from(u32_at(end64, 16));
    record.disk_start = u64::from(u32_at(end64, 20));
    record.entries_total = u64_at(end64, 32);
    record.size = dir_size;
    record.offset = dir_offset;
    record.location = offset - extra;
    Ok(record)
}

fn parse_end_record(bytes: &[u8], location: usize) -> EndRecord {
    EndRecord {
        disk_number: u64::from(u16_at(bytes, 4)),
        disk_start: u64::from(u16_at(bytes, 6)),
        entries_total: u64::from(u16_at(bytes, 10)),
        size: u64::from(u32_at(bytes, 12)),
        offset: u64::from(u32_at(bytes, 16)),
        location: location as i128,
    }
}

/// `_EndRecData`.
fn end_record(data: &[u8]) -> PyResult<Option<EndRecord>> {
    let size = data.len();
    let tail = &data[size.saturating_sub(SIZE_END)..];
    if tail.len() == SIZE_END && &tail[0..4] == STRING_END && tail[SIZE_END - 2..] == [0, 0] {
        let record = parse_end_record(tail, size - SIZE_END);
        return end_record64(data, (size - SIZE_END) as i128, record).map(Some);
    }
    let comment_start = size.saturating_sub(MAX_COMMENT + SIZE_END);
    let search = &data[comment_start..];
    let Some(start) = memchr::memmem::rfind(search, STRING_END) else {
        return Ok(None);
    };
    let bytes = &search[start..search.len().min(start + SIZE_END)];
    if bytes.len() != SIZE_END {
        return Ok(None);
    }
    let location = comment_start + start;
    end_record64(data, location as i128, parse_end_record(bytes, location)).map(Some)
}

/// `_check_zipfile` under `is_zipfile`, which catches OSError and BadZipFile, but not what seeking a
/// BytesIO before its start raises.
pub fn check_zipfile(data: &[u8]) -> PyResult<bool> {
    let record = match end_record(data) {
        Ok(Some(record)) => record,
        Ok(None) => return Ok(false),
        Err(error) if error.kind == "OSError" || error.kind == "BadZipFile" => return Ok(false),
        Err(error) => return Err(error),
    };
    if record.entries_total == 0 && record.size == 0 && record.offset == 0 {
        return Ok(true);
    }
    if record.disk_number != record.disk_start {
        return Ok(false);
    }
    let start = record.location - i128::from(record.size);
    check_seek(start)?;
    if record.size >= SIZE_CENTRAL as u64 {
        let central = slice_at(data, start, SIZE_CENTRAL);
        if central.len() == SIZE_CENTRAL && &central[0..4] == STRING_CENTRAL {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `zipfile.is_zipfile` on a BytesIO, for files where it returns. On the few where Python raises
/// ValueError (a central directory larger than what precedes it) this is false; `check_zipfile`
/// tells them apart.
pub fn is_zipfile(data: &[u8]) -> bool {
    check_zipfile(data).unwrap_or(false)
}

#[derive(Debug)]
struct Info {
    orig_filename: String,
    filename: String,
    flag_bits: u16,
    compress_type: u16,
    crc: u32,
    compress_size: u64,
    file_size: u64,
    header_offset: i128,
    end_offset: i128,
}

/// `ZipInfo._decodeExtra`, on what the constructor reads: sizes, offset and name, by reference.
fn decode_extra(
    mut extra: &[u8],
    name_crc: u32,
    file_size: &mut u64,
    compress_size: &mut u64,
    header_offset: &mut u64,
    filename: &mut String,
) -> PyResult<()> {
    while extra.len() >= 4 {
        let tp = u16_at(extra, 0);
        let ln = usize::from(u16_at(extra, 2));
        if ln + 4 > extra.len() {
            return Err(bad_zip(format!("Corrupt extra field {tp:04x} (size={ln})")));
        }
        let mut field = &extra[4..ln + 4];
        if tp == 0x0001 {
            let not_found =
                |what: &str| bad_zip(format!("Corrupt zip64 extra field. {what} not found."));
            if *file_size == u64::MAX || *file_size == 0xFFFF_FFFF {
                if field.len() < 8 {
                    return Err(not_found("File size"));
                }
                *file_size = u64_at(field, 0);
                field = &field[8..];
            }
            if *compress_size == 0xFFFF_FFFF {
                if field.len() < 8 {
                    return Err(not_found("Compress size"));
                }
                *compress_size = u64_at(field, 0);
                field = &field[8..];
            }
            if *header_offset == 0xFFFF_FFFF {
                if field.len() < 8 {
                    return Err(not_found("Header offset"));
                }
                *header_offset = u64_at(field, 0);
            }
        } else if tp == 0x7075 {
            if field.len() < 5 {
                return Err(bad_zip("Corrupt unicode path extra field (0x7075)"));
            }
            if field[0] == 1 && u32_at(field, 1) == name_crc {
                let name = std::str::from_utf8(&field[5..]).map_err(|_| {
                    bad_zip("Corrupt unicode path extra field (0x7075): invalid utf-8 bytes")
                })?;
                // Python warns about an empty one, which nothing here turns into an error
                if !name.is_empty() {
                    *filename = sanitize(name);
                }
            }
        }
        extra = &extra[ln + 4..];
    }
    Ok(())
}

/// A `zipfile.ZipFile` over bytes, opened for reading.
#[derive(Debug)]
pub struct ZipFile<'a> {
    data: &'a [u8],
    filelist: Vec<Info>,
    name_to_info: HashMap<String, usize>,
}

impl ZipFile<'_> {
    /// The constructor, which is `_RealGetContents`.
    pub fn new(data: &[u8]) -> PyResult<ZipFile<'_>> {
        let not_zip = || bad_zip("File is not a zip file");
        let record = match end_record(data) {
            Ok(Some(record)) => record,
            Ok(None) => return Err(not_zip()),
            Err(error) if error.kind == "OSError" => return Err(not_zip()),
            Err(error) => return Err(error),
        };
        let size_cd = record.size;
        let concat = record.location - i128::from(size_cd) - i128::from(record.offset);
        let start_dir = i128::from(record.offset) + concat;
        if start_dir < 0 {
            return Err(bad_zip("Bad offset for central directory"));
        }
        let directory = slice_at(
            data,
            start_dir,
            usize::try_from(size_cd).unwrap_or(usize::MAX),
        );
        let mut at = 0usize;
        let mut total = 0u64;
        let mut filelist = Vec::new();
        let mut name_to_info = HashMap::new();
        while total < size_cd {
            let central = slice_at(directory, at as i128, SIZE_CENTRAL);
            if central.len() != SIZE_CENTRAL {
                return Err(bad_zip("Truncated central directory"));
            }
            at += SIZE_CENTRAL;
            if &central[0..4] != STRING_CENTRAL {
                return Err(bad_zip("Bad magic number for central directory"));
            }
            let name_len = usize::from(u16_at(central, 28));
            let extra_len = usize::from(u16_at(central, 30));
            let comment_len = usize::from(u16_at(central, 32));
            let raw_name = slice_at(directory, at as i128, name_len);
            at += raw_name.len();
            let name_crc = crc32fast::hash(raw_name);
            let flag_bits = u16_at(central, 8);
            let orig_filename = decode_name(raw_name, flag_bits)?;
            let mut filename = sanitize(&orig_filename);
            let extra = slice_at(directory, at as i128, extra_len);
            at += extra.len();
            at += slice_at(directory, at as i128, comment_len).len();
            let extract_version = central[6];
            if extract_version > MAX_EXTRACT_VERSION {
                let version = f64::from(extract_version) / 10.0;
                return Err(PyErr::new(
                    "NotImplementedError",
                    format!("zip file version {version:.1}"),
                ));
            }
            let mut compress_size = u64::from(u32_at(central, 20));
            let mut file_size = u64::from(u32_at(central, 24));
            let mut header_offset = u64::from(u32_at(central, 42));
            decode_extra(
                extra,
                name_crc,
                &mut file_size,
                &mut compress_size,
                &mut header_offset,
                &mut filename,
            )?;
            name_to_info.insert(filename.clone(), filelist.len());
            filelist.push(Info {
                orig_filename,
                filename,
                flag_bits,
                compress_type: u16_at(central, 10),
                crc: u32_at(central, 16),
                compress_size,
                file_size,
                header_offset: i128::from(header_offset) + concat,
                end_offset: 0,
            });
            total += (SIZE_CENTRAL + name_len + extra_len + comment_len) as u64;
        }
        // sorted() is stable, and this walks it backwards
        let mut order: Vec<usize> = (0..filelist.len()).collect();
        order.sort_by_key(|&index| filelist[index].header_offset);
        let mut end_offset = start_dir;
        for &index in order.iter().rev() {
            filelist[index].end_offset = end_offset;
            end_offset = filelist[index].header_offset;
        }
        Ok(ZipFile {
            data,
            filelist,
            name_to_info,
        })
    }

    /// `namelist()`: every entry's name in order, duplicates included.
    pub fn namelist(&self) -> Vec<&str> {
        self.filelist
            .iter()
            .map(|info| info.filename.as_str())
            .collect()
    }

    /// `getinfo(name)` not raising KeyError. Of duplicates, the last wins.
    pub fn contains(&self, name: &str) -> bool {
        self.name_to_info.contains_key(name)
    }

    /// The entry at `index` of `namelist()`, opened as `z.open(zinfo)`, then `read(limit)`, or
    /// `read()` for None. `z.open(name)` always opens the last entry of a duplicated name: for that,
    /// which is what olevba's `for subfile in z.namelist()` does, call `open_read`.
    pub fn read_member(&self, index: usize, limit: Option<usize>) -> PyResult<Vec<u8>> {
        let info = self
            .filelist
            .get(index)
            .ok_or_else(|| PyErr::new("IndexError", "list index out of range"))?;
        self.open(info)?.read(limit)
    }

    /// `z.open(name)` then `read(limit)`, or `read()` for None.
    pub fn open_read(&self, name: &str, limit: Option<usize>) -> PyResult<Vec<u8>> {
        let Some(&index) = self.name_to_info.get(name) else {
            let message = format!("There is no item named {} in the archive", repr_str(name));
            // str(KeyError) is the repr of its argument
            return Err(PyErr::new("KeyError", repr_str(&message)));
        };
        self.open(&self.filelist[index])?.read(limit)
    }

    /// `ZipFile.read(name)`.
    pub fn read(&self, name: &str) -> PyResult<Vec<u8>> {
        self.open_read(name, None)
    }

    /// `ZipFile.open`, for reading, after finding the entry.
    fn open<'s>(&'s self, info: &'s Info) -> PyResult<MemberReader<'s>> {
        check_seek(info.header_offset)?;
        let header = slice_at(self.data, info.header_offset, SIZE_FILE);
        if header.len() != SIZE_FILE {
            return Err(bad_zip("Truncated file header"));
        }
        if &header[0..4] != STRING_FILE {
            return Err(bad_zip("Bad magic number for file header"));
        }
        let mut at = info.header_offset + SIZE_FILE as i128;
        let name = slice_at(self.data, at, usize::from(u16_at(header, 26)));
        at += name.len() as i128;
        at += i128::from(u16_at(header, 28));
        if info.flag_bits & FLAG_PATCH != 0 {
            return Err(PyErr::new(
                "NotImplementedError",
                "compressed patched data (flag bit 5)",
            ));
        }
        if info.flag_bits & FLAG_STRONG != 0 {
            return Err(PyErr::new(
                "NotImplementedError",
                "strong encryption (flag bit 6)",
            ));
        }
        if decode_name(name, u16_at(header, 6))? != info.orig_filename {
            return Err(bad_zip(format!(
                "File name in directory {} and header {} differ.",
                repr_str(&info.orig_filename),
                repr_bytes(name)
            )));
        }
        // when the end is the header itself, Python only warns
        if at + i128::from(info.compress_size) > info.end_offset
            && info.end_offset != info.header_offset
        {
            return Err(bad_zip(format!(
                "Overlapped entries: {} (possible zip bomb)",
                repr_str(&info.orig_filename)
            )));
        }
        if info.flag_bits & FLAG_ENCRYPTED != 0 {
            return Err(PyErr::new(
                "RuntimeError",
                format!(
                    "File {} is encrypted, password required for extraction",
                    repr_str(&info.filename)
                ),
            ));
        }
        let decompressor = match info.compress_type {
            STORED => Decompressor::Stored,
            DEFLATED => Decompressor::Deflate(Box::new(Inflate::new())),
            BZIP2 => Decompressor::Bzip2(Box::new(bzip2::Decompress::new(false))),
            LZMA => Decompressor::Lzma(None),
            // Python has compression.zstd, this has no decoder for it
            ZSTANDARD => {
                return Err(PyErr::new(
                    "NotImplementedError",
                    "compression type 93 (zstd)",
                ));
            }
            _ => {
                return Err(PyErr::new(
                    "NotImplementedError",
                    "That compression method is not supported",
                ));
            }
        };
        let start = usize::try_from(at)
            .unwrap_or(usize::MAX)
            .min(self.data.len());
        Ok(MemberReader {
            data: self.data,
            name: &info.filename,
            position: start,
            input_at: start,
            compress_left: i128::from(info.compress_size),
            left: i128::from(info.file_size),
            decompressor,
            needs_input: true,
            decompressor_eof: false,
            eof: false,
            running_crc: 0,
            expected_crc: info.crc,
        })
    }
}

enum Decompressor {
    Stored,
    Deflate(Box<Inflate>),
    Bzip2(Box<bzip2::Decompress>),
    Lzma(Option<Box<LzmaDecoder>>),
}

/// Where a decompressor puts what it makes: the part `data[:self._left]` will keep. The rest costs
/// no memory, so that a bomb in a member that claims to be small only takes time.
struct Sink {
    kept: Vec<u8>,
    keep: usize,
}

impl Sink {
    fn new(left: i128) -> Sink {
        let keep = left.clamp(0, MAX_MEMBER as i128 + 1) as usize;
        Sink {
            kept: Vec::new(),
            keep,
        }
    }

    #[inline]
    fn push(&mut self, byte: u8) {
        if self.kept.len() < self.keep {
            self.kept.push(byte);
        }
    }

    fn extend(&mut self, bytes: &[u8]) {
        let room = self.keep - self.kept.len();
        self.kept.extend_from_slice(&bytes[..bytes.len().min(room)]);
    }

    fn overflowed(&self) -> bool {
        self.kept.len() > MAX_MEMBER
    }
}

/// `ZipExtFile`. The compressed bytes are contiguous in the file, so what a decompressor has been
/// given and hasn't used is the range from `input_at` to `position`.
struct MemberReader<'a> {
    data: &'a [u8],
    name: &'a str,
    position: usize,
    input_at: usize,
    compress_left: i128,
    left: i128,
    decompressor: Decompressor,
    needs_input: bool,
    decompressor_eof: bool,
    eof: bool,
    running_crc: u32,
    expected_crc: u32,
}

impl MemberReader<'_> {
    /// `ZipExtFile.read(limit)` on a new file object, so with no read buffer.
    fn read(&mut self, limit: Option<usize>) -> PyResult<Vec<u8>> {
        let mut buffer = Vec::new();
        match limit {
            None => {
                while !self.eof {
                    let data = self.read1(MAX_N)?;
                    if buffer.len() + data.len() > MAX_MEMBER {
                        return Err(memory_error());
                    }
                    buffer.extend_from_slice(&data);
                }
            }
            Some(mut n) => {
                while n > 0 && !self.eof {
                    let data = self.read1(n)?;
                    if n < data.len() {
                        buffer.extend_from_slice(&data[..n]);
                        break;
                    }
                    if buffer.len() + data.len() > MAX_MEMBER {
                        return Err(memory_error());
                    }
                    buffer.extend_from_slice(&data);
                    n -= data.len();
                }
            }
        }
        Ok(buffer)
    }

    /// `_read2`: gives the decompressor more of the file, returning how much.
    fn read2(&mut self, n: usize) -> PyResult<usize> {
        if self.compress_left <= 0 {
            return Ok(0);
        }
        let n = (n.max(MIN_READ_SIZE) as i128).min(self.compress_left) as usize;
        let got = n.min(self.data.len() - self.position);
        self.position += got;
        self.compress_left -= got as i128;
        if got == 0 {
            return Err(PyErr::new("EOFError", ""));
        }
        Ok(got)
    }

    /// `_read1`.
    fn read1(&mut self, n: usize) -> PyResult<Vec<u8>> {
        if self.eof || n == 0 {
            return Ok(Vec::new());
        }
        let mut sink = Sink::new(self.left);
        let limit = n.max(MIN_READ_SIZE) as u64;
        match self.decompressor {
            Decompressor::Stored => {
                let start = self.position;
                self.read2(n)?;
                sink.extend(&self.data[start..self.position]);
                self.eof = self.compress_left <= 0;
            }
            Decompressor::Deflate(_) => self.read1_deflate(n, limit, &mut sink)?,
            Decompressor::Bzip2(_) => self.read1_bzip2(n, limit, &mut sink)?,
            Decompressor::Lzma(_) => self.read1_lzma(n, limit, &mut sink)?,
        }
        if sink.overflowed() {
            return Err(memory_error());
        }
        let data = sink.kept;
        self.left -= data.len() as i128;
        if self.left <= 0 {
            self.eof = true;
        }
        let mut hasher = crc32fast::Hasher::new_with_initial(self.running_crc);
        hasher.update(&data);
        self.running_crc = hasher.finalize();
        if self.eof && self.running_crc != self.expected_crc {
            return Err(bad_zip(format!(
                "Bad CRC-32 for file {}",
                repr_str(self.name)
            )));
        }
        Ok(data)
    }

    fn read1_deflate(&mut self, n: usize, limit: u64, sink: &mut Sink) -> PyResult<()> {
        let tail = self.position - self.input_at;
        if n > tail {
            self.read2(n - tail)?;
        }
        let Decompressor::Deflate(inflate) = &mut self.decompressor else {
            unreachable!("called for deflate");
        };
        let input = &self.data[..self.position];
        let status = inflate.run(input, &mut self.input_at, limit, sink);
        match status {
            Inflated::Error(message) => {
                return Err(PyErr::new(
                    "error",
                    format!("Error -3 while decompressing data: {message}"),
                ));
            }
            Inflated::End => self.eof = true,
            Inflated::Partial => {
                self.eof = self.compress_left <= 0 && self.input_at == self.position;
            }
        }
        if self.eof && !sink.overflowed() {
            // flush(): no input, Z_FINISH, and an error only stops it
            inflate.run(input, &mut self.input_at, u64::MAX, sink);
        }
        Ok(())
    }

    fn read1_bzip2(&mut self, n: usize, limit: u64, sink: &mut Sink) -> PyResult<()> {
        if self.needs_input {
            self.read2(n)?;
        }
        let Decompressor::Bzip2(bz) = &mut self.decompressor else {
            unreachable!("called for bzip2");
        };
        let input = &self.data[self.input_at..self.position];
        let used = bz2_decompress(bz, input, limit, sink, &mut self.decompressor_eof)?;
        self.input_at += used;
        self.needs_input = !self.decompressor_eof && self.input_at == self.position;
        self.eof = self.decompressor_eof || (self.compress_left <= 0 && self.needs_input);
        Ok(())
    }

    fn read1_lzma(&mut self, n: usize, limit: u64, sink: &mut Sink) -> PyResult<()> {
        if self.needs_input {
            self.read2(n)?;
        }
        let Decompressor::Lzma(decoder) = &mut self.decompressor else {
            unreachable!("called for lzma");
        };
        if decoder.is_none() {
            // zipfile.LZMADecompressor buffers its 4-byte header and the properties
            let header = &self.data[self.input_at..self.position];
            if header.len() > 4 {
                let size = usize::from(u16_at(header, 2));
                if header.len() > 4 + size {
                    self.input_at += 4 + size;
                    *decoder = Some(Box::new(LzmaDecoder::new(
                        &header[4..4 + size],
                        self.input_at,
                    )?));
                }
            }
        }
        match decoder {
            None => {
                self.eof = self.compress_left <= 0;
            }
            Some(decoder) => {
                let input = &self.data[..self.position];
                let status = decoder.decode(input, &mut self.input_at, limit, sink)?;
                self.decompressor_eof = status == LzmaStatus::End;
                // both empty leaves a little to output next time, so Python wants no input
                self.needs_input = status == LzmaStatus::NeedInput && decoder.produced_now < limit;
                self.eof = self.decompressor_eof || (self.compress_left <= 0 && self.needs_input);
            }
        }
        Ok(())
    }
}

/// `_BlocksOutputBuffer`'s sizes. They show in bzip2, whose decompress_buf stops at the end of a
/// block once the input is used up, even with output pending.
fn next_block(blocks: &mut usize, allocated: u64, limit: u64) -> u64 {
    const SIZES: [u64; 17] = [
        32 << 10,
        64 << 10,
        256 << 10,
        1 << 20,
        4 << 20,
        8 << 20,
        16 << 20,
        16 << 20,
        32 << 20,
        32 << 20,
        32 << 20,
        32 << 20,
        64 << 20,
        64 << 20,
        128 << 20,
        128 << 20,
        256 << 20,
    ];
    let size = SIZES[(*blocks).min(SIZES.len() - 1)];
    *blocks += 1;
    size.min(limit - allocated)
}

/// `BZ2Decompressor.decompress(data, limit)`. Returns how much of the input it used.
fn bz2_decompress(
    bz: &mut bzip2::Decompress,
    input: &[u8],
    limit: u64,
    sink: &mut Sink,
    eof: &mut bool,
) -> PyResult<usize> {
    let mut chunk = vec![0u8; 64 * 1024];
    let mut used = 0usize;
    let mut blocks = 0usize;
    let mut allocated = next_block(&mut blocks, 0, limit);
    let mut avail_out = allocated;
    loop {
        let size = avail_out.min(chunk.len() as u64) as usize;
        let (in_before, out_before) = (bz.total_in(), bz.total_out());
        let status =
            bz.decompress(&input[used..], &mut chunk[..size])
                .map_err(|error| match error {
                    bzip2::Error::Sequence => PyErr::new(
                        "ValueError",
                        "Invalid sequence of commands sent to libbzip2",
                    ),
                    bzip2::Error::Param => PyErr::new(
                        "ValueError",
                        "Internal error - invalid parameters passed to libbzip2",
                    ),
                    bzip2::Error::Data | bzip2::Error::DataMagic => {
                        PyErr::new("OSError", "Invalid data stream")
                    }
                })?;
        let in_step = (bz.total_in() - in_before) as usize;
        let out_step = (bz.total_out() - out_before) as usize;
        used += in_step;
        avail_out -= out_step as u64;
        sink.extend(&chunk[..out_step]);
        if matches!(status, bzip2::Status::StreamEnd) {
            *eof = true;
            break;
        }
        if sink.overflowed() {
            break;
        }
        // this chunk filled and the block didn't: Python's one call is still running
        if out_step == size && avail_out > 0 {
            continue;
        }
        if used == input.len() {
            break;
        }
        if avail_out == 0 {
            if allocated == limit {
                break;
            }
            let block = next_block(&mut blocks, allocated, limit);
            allocated += block;
            avail_out = block;
        } else if in_step == 0 && out_step == 0 {
            break;
        }
    }
    Ok(used)
}

// Deflate, as zlib 1.3.1's inflate() with windowBits -15 and without inflate_fast, which only reads
// ahead and gives back what it didn't use.

#[derive(Clone, Copy, Default)]
struct Code {
    op: u8,
    bits: u8,
    val: u16,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CodeType {
    Codes,
    Lens,
    Dists,
}

const MAXBITS: usize = 15;
const ENOUGH_LENS: u32 = 852;
const ENOUGH_DISTS: u32 = 592;

const LBASE: [u16; 31] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258, 0, 0,
];
const LEXT: [u8; 31] = [
    16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18, 19, 19, 19, 19, 20, 20, 20, 20,
    21, 21, 21, 21, 16, 203, 77,
];
const DBASE: [u16; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 0, 0,
];
const DEXT: [u8; 32] = [
    16, 16, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22, 23, 23, 24, 24, 25, 25, 26, 26,
    27, 27, 28, 28, 29, 29, 64, 64,
];

/// `inflate_table`. Returns the table and its root bits, or None for a set of lengths it refuses.
fn inflate_table(kind: CodeType, lens: &[u16], root_bits: u32) -> Option<(Vec<Code>, u32)> {
    let mut count = [0u16; MAXBITS + 1];
    for &len in lens {
        count[usize::from(len)] += 1;
    }
    let mut root = root_bits as usize;
    let mut max = MAXBITS;
    while max >= 1 && count[max] == 0 {
        max -= 1;
    }
    if root > max {
        root = max;
    }
    if max == 0 {
        let here = Code {
            op: 64,
            bits: 1,
            val: 0,
        };
        return Some((vec![here, here], 1));
    }
    let mut min = 1;
    while min < max && count[min] == 0 {
        min += 1;
    }
    if root < min {
        root = min;
    }
    let mut left = 1i32;
    for &number in &count[1..=MAXBITS] {
        left <<= 1;
        left -= i32::from(number);
        if left < 0 {
            return None;
        }
    }
    if left > 0 && (kind == CodeType::Codes || max != 1) {
        return None;
    }
    let mut offs = [0u16; MAXBITS + 1];
    for len in 1..MAXBITS {
        offs[len + 1] = offs[len] + count[len];
    }
    let mut work = [0u16; 320];
    for (sym, &len) in lens.iter().enumerate() {
        if len != 0 {
            work[usize::from(offs[usize::from(len)])] = sym as u16;
            offs[usize::from(len)] += 1;
        }
    }
    let matched: u32 = match kind {
        CodeType::Codes => 20,
        CodeType::Lens => 257,
        CodeType::Dists => 0,
    };
    let too_big = |used: u32| {
        (kind == CodeType::Lens && used > ENOUGH_LENS)
            || (kind == CodeType::Dists && used > ENOUGH_DISTS)
    };
    let mut huff = 0u32;
    let mut sym = 0usize;
    let mut len = min;
    let mut next = 0usize;
    let mut curr = root;
    let mut drop = 0usize;
    let mut low = u32::MAX;
    let mut used = 1u32 << root;
    let mask = used - 1;
    if too_big(used) {
        return None;
    }
    let mut table = vec![Code::default(); 1 << root];
    loop {
        let symbol = u32::from(work[sym]);
        let mut here = Code {
            op: 0,
            bits: (len - drop) as u8,
            val: 0,
        };
        if symbol + 1 < matched {
            here.val = work[sym];
        } else if symbol >= matched {
            let index = (symbol - matched) as usize;
            if kind == CodeType::Lens {
                here.op = LEXT[index];
                here.val = LBASE[index];
            } else {
                here.op = DEXT[index];
                here.val = DBASE[index];
            }
        } else {
            here.op = 32 + 64;
        }
        let incr = 1usize << (len - drop);
        let mut fill = 1usize << curr;
        let size = fill;
        loop {
            fill -= incr;
            table[next + (huff as usize >> drop) + fill] = here;
            if fill == 0 {
                break;
            }
        }
        let mut step = 1u32 << (len - 1);
        while huff & step != 0 {
            step >>= 1;
        }
        if step != 0 {
            huff &= step - 1;
            huff += step;
        } else {
            huff = 0;
        }
        sym += 1;
        count[len] -= 1;
        if count[len] == 0 {
            if len == max {
                break;
            }
            len = usize::from(lens[usize::from(work[sym])]);
        }
        if len > root && (huff & mask) != low {
            if drop == 0 {
                drop = root;
            }
            next += size;
            curr = len - drop;
            let mut spare = 1i32 << curr;
            while curr + drop < max {
                spare -= i32::from(count[curr + drop]);
                if spare <= 0 {
                    break;
                }
                curr += 1;
                spare <<= 1;
            }
            used += 1 << curr;
            if too_big(used) {
                return None;
            }
            table.resize(next + (1 << curr), Code::default());
            low = huff & mask;
            table[low as usize] = Code {
                op: curr as u8,
                bits: root as u8,
                val: next as u16,
            };
        }
    }
    if huff != 0 {
        let index = next + huff as usize;
        table[index] = Code {
            op: 64,
            bits: (len - drop) as u8,
            val: 0,
        };
    }
    Some((table, root as u32))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Type,
    Stored,
    Copy,
    Table,
    LenLens,
    CodeLens,
    Len,
    LenExt,
    Dist,
    DistExt,
    Match,
    Lit,
    Done,
    Bad,
}

#[derive(Debug, PartialEq, Eq)]
enum Inflated {
    Partial,
    End,
    Error(&'static str),
}

struct Inflate {
    mode: Mode,
    last: bool,
    hold: u64,
    bits: u32,
    length: u32,
    offset: u32,
    extra: u32,
    nlen: usize,
    ndist: usize,
    ncode: usize,
    have: usize,
    lens: [u16; 320],
    len_table: Vec<Code>,
    dist_table: Vec<Code>,
    len_bits: u32,
    dist_bits: u32,
    window: Box<[u8; 32768]>,
    window_at: usize,
    total: u64,
    message: &'static str,
}

const ORDER: [u8; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

macro_rules! need_bits {
    ($self:ident, $input:ident, $at:ident, $n:expr) => {
        while $self.bits < $n {
            if *$at >= $input.len() {
                return Inflated::Partial;
            }
            $self.hold |= u64::from($input[*$at]) << $self.bits;
            *$at += 1;
            $self.bits += 8;
        }
    };
}

/// A table lookup, pulling bytes until the code it finds is complete.
macro_rules! lookup {
    ($self:ident, $input:ident, $at:ident, $table:expr, $base:expr, $width:expr, $skip:expr) => {
        loop {
            let index = ($self.hold & ((1u64 << $width) - 1)) as usize >> $skip;
            let here = $table[$base + index];
            if u32::from(here.bits) + $skip <= $self.bits {
                break here;
            }
            if *$at >= $input.len() {
                return Inflated::Partial;
            }
            $self.hold |= u64::from($input[*$at]) << $self.bits;
            *$at += 1;
            $self.bits += 8;
        }
    };
}

impl Inflate {
    fn new() -> Inflate {
        Inflate {
            mode: Mode::Type,
            last: false,
            hold: 0,
            bits: 0,
            length: 0,
            offset: 0,
            extra: 0,
            nlen: 0,
            ndist: 0,
            ncode: 0,
            have: 0,
            lens: [0; 320],
            len_table: Vec::new(),
            dist_table: Vec::new(),
            len_bits: 0,
            dist_bits: 0,
            window: vec![0u8; 32768]
                .into_boxed_slice()
                .try_into()
                .expect("the right size"),
            window_at: 0,
            total: 0,
            message: "",
        }
    }

    #[inline]
    fn drop_bits(&mut self, count: u32) {
        self.hold >>= count;
        self.bits -= count;
    }

    #[inline]
    fn take_bits(&mut self, count: u32) -> u32 {
        let value = (self.hold & ((1u64 << count) - 1)) as u32;
        self.drop_bits(count);
        value
    }

    #[inline]
    fn emit(&mut self, byte: u8, sink: &mut Sink) {
        self.window[self.window_at] = byte;
        self.window_at = (self.window_at + 1) & 32767;
        self.total += 1;
        sink.push(byte);
    }

    fn fail(&mut self, message: &'static str) {
        self.message = message;
        self.mode = Mode::Bad;
    }

    /// inflate() with `limit` bytes of output room. What it returns as Partial covers both Z_OK and
    /// Z_BUF_ERROR, which Python treats alike.
    fn run(&mut self, input: &[u8], at: &mut usize, limit: u64, sink: &mut Sink) -> Inflated {
        let mut left = limit;
        self.step(input, at, &mut left, sink)
    }

    fn step(&mut self, input: &[u8], at: &mut usize, left: &mut u64, sink: &mut Sink) -> Inflated {
        loop {
            match self.mode {
                Mode::Type => {
                    if self.last {
                        self.drop_bits(self.bits & 7);
                        self.mode = Mode::Done;
                        continue;
                    }
                    need_bits!(self, input, at, 3);
                    self.last = self.take_bits(1) == 1;
                    match self.take_bits(2) {
                        0 => self.mode = Mode::Stored,
                        1 => {
                            let mut lens = [8u16; 288];
                            lens[144..256].fill(9);
                            lens[256..280].fill(7);
                            let fixed = inflate_table(CodeType::Lens, &lens, 9);
                            (self.len_table, self.len_bits) = fixed.expect("the fixed code");
                            let fixed = inflate_table(CodeType::Dists, &[5u16; 32], 5);
                            (self.dist_table, self.dist_bits) = fixed.expect("the fixed code");
                            self.mode = Mode::Len;
                        }
                        2 => self.mode = Mode::Table,
                        _ => self.fail("invalid block type"),
                    }
                }
                Mode::Stored => {
                    self.drop_bits(self.bits & 7);
                    need_bits!(self, input, at, 32);
                    if (self.hold & 0xffff) != ((self.hold >> 16) ^ 0xffff) {
                        self.fail("invalid stored block lengths");
                        continue;
                    }
                    self.length = (self.hold & 0xffff) as u32;
                    self.hold = 0;
                    self.bits = 0;
                    self.mode = Mode::Copy;
                }
                Mode::Copy => {
                    if self.length != 0 {
                        let copy = u64::from(self.length)
                            .min((input.len() - *at) as u64)
                            .min(*left) as usize;
                        if copy == 0 {
                            return Inflated::Partial;
                        }
                        for index in 0..copy {
                            self.emit(input[*at + index], sink);
                        }
                        *at += copy;
                        *left -= copy as u64;
                        self.length -= copy as u32;
                    } else {
                        self.mode = Mode::Type;
                    }
                }
                Mode::Table => {
                    need_bits!(self, input, at, 14);
                    self.nlen = self.take_bits(5) as usize + 257;
                    self.ndist = self.take_bits(5) as usize + 1;
                    self.ncode = self.take_bits(4) as usize + 4;
                    if self.nlen > 286 || self.ndist > 30 {
                        self.fail("too many length or distance symbols");
                        continue;
                    }
                    self.have = 0;
                    self.mode = Mode::LenLens;
                }
                Mode::LenLens => {
                    while self.have < self.ncode {
                        need_bits!(self, input, at, 3);
                        self.lens[usize::from(ORDER[self.have])] = self.take_bits(3) as u16;
                        self.have += 1;
                    }
                    while self.have < 19 {
                        self.lens[usize::from(ORDER[self.have])] = 0;
                        self.have += 1;
                    }
                    match inflate_table(CodeType::Codes, &self.lens[..19], 7) {
                        Some((table, bits)) => {
                            self.len_table = table;
                            self.len_bits = bits;
                            self.have = 0;
                            self.mode = Mode::CodeLens;
                        }
                        None => self.fail("invalid code lengths set"),
                    }
                }
                Mode::CodeLens => {
                    let total = self.nlen + self.ndist;
                    while self.have < total {
                        let here = lookup!(self, input, at, self.len_table, 0, self.len_bits, 0u32);
                        let bits = u32::from(here.bits);
                        if here.val < 16 {
                            self.drop_bits(bits);
                            self.lens[self.have] = here.val;
                            self.have += 1;
                            continue;
                        }
                        let (len, copy);
                        if here.val == 16 {
                            need_bits!(self, input, at, bits + 2);
                            self.drop_bits(bits);
                            if self.have == 0 {
                                self.fail("invalid bit length repeat");
                                break;
                            }
                            len = self.lens[self.have - 1];
                            copy = 3 + self.take_bits(2) as usize;
                        } else if here.val == 17 {
                            need_bits!(self, input, at, bits + 3);
                            self.drop_bits(bits);
                            len = 0;
                            copy = 3 + self.take_bits(3) as usize;
                        } else {
                            need_bits!(self, input, at, bits + 7);
                            self.drop_bits(bits);
                            len = 0;
                            copy = 11 + self.take_bits(7) as usize;
                        }
                        if self.have + copy > total {
                            self.fail("invalid bit length repeat");
                            break;
                        }
                        self.lens[self.have..self.have + copy].fill(len);
                        self.have += copy;
                    }
                    if self.mode == Mode::Bad {
                        continue;
                    }
                    if self.lens[256] == 0 {
                        self.fail("invalid code -- missing end-of-block");
                        continue;
                    }
                    let Some((table, bits)) =
                        inflate_table(CodeType::Lens, &self.lens[..self.nlen], 9)
                    else {
                        self.fail("invalid literal/lengths set");
                        continue;
                    };
                    self.len_table = table;
                    self.len_bits = bits;
                    let dists = &self.lens[self.nlen..self.nlen + self.ndist];
                    let Some((table, bits)) = inflate_table(CodeType::Dists, dists, 6) else {
                        self.fail("invalid distances set");
                        continue;
                    };
                    self.dist_table = table;
                    self.dist_bits = bits;
                    self.mode = Mode::Len;
                }
                Mode::Len => {
                    let mut here = lookup!(self, input, at, self.len_table, 0, self.len_bits, 0u32);
                    if here.op != 0 && here.op & 0xf0 == 0 {
                        let last = here;
                        let last_bits = u32::from(last.bits);
                        let width = last_bits + u32::from(last.op);
                        here = lookup!(
                            self,
                            input,
                            at,
                            self.len_table,
                            usize::from(last.val),
                            width,
                            last_bits
                        );
                        self.drop_bits(last_bits);
                    }
                    self.drop_bits(u32::from(here.bits));
                    self.length = u32::from(here.val);
                    if here.op == 0 {
                        self.mode = Mode::Lit;
                    } else if here.op & 32 != 0 {
                        self.mode = Mode::Type;
                    } else if here.op & 64 != 0 {
                        self.fail("invalid literal/length code");
                    } else {
                        self.extra = u32::from(here.op) & 15;
                        self.mode = Mode::LenExt;
                    }
                }
                Mode::LenExt => {
                    if self.extra != 0 {
                        need_bits!(self, input, at, self.extra);
                        self.length += self.take_bits(self.extra);
                    }
                    self.mode = Mode::Dist;
                }
                Mode::Dist => {
                    let mut here =
                        lookup!(self, input, at, self.dist_table, 0, self.dist_bits, 0u32);
                    if here.op & 0xf0 == 0 {
                        let last = here;
                        let last_bits = u32::from(last.bits);
                        let width = last_bits + u32::from(last.op);
                        here = lookup!(
                            self,
                            input,
                            at,
                            self.dist_table,
                            usize::from(last.val),
                            width,
                            last_bits
                        );
                        self.drop_bits(last_bits);
                    }
                    self.drop_bits(u32::from(here.bits));
                    if here.op & 64 != 0 {
                        self.fail("invalid distance code");
                        continue;
                    }
                    self.offset = u32::from(here.val);
                    self.extra = u32::from(here.op) & 15;
                    self.mode = Mode::DistExt;
                }
                Mode::DistExt => {
                    if self.extra != 0 {
                        need_bits!(self, input, at, self.extra);
                        self.offset += self.take_bits(self.extra);
                    }
                    self.mode = Mode::Match;
                }
                Mode::Match => {
                    if *left == 0 {
                        return Inflated::Partial;
                    }
                    if u64::from(self.offset) > self.total {
                        self.fail("invalid distance too far back");
                        continue;
                    }
                    let copy = u64::from(self.length).min(*left) as u32;
                    let distance = self.offset as usize;
                    for _ in 0..copy {
                        let from = self.window_at.wrapping_sub(distance) & 32767;
                        let byte = self.window[from];
                        self.emit(byte, sink);
                    }
                    *left -= u64::from(copy);
                    self.length -= copy;
                    if self.length == 0 {
                        self.mode = Mode::Len;
                    }
                    if sink.overflowed() {
                        return Inflated::Partial;
                    }
                }
                Mode::Lit => {
                    if *left == 0 {
                        return Inflated::Partial;
                    }
                    self.emit(self.length as u8, sink);
                    *left -= 1;
                    self.mode = Mode::Len;
                }
                Mode::Done => return Inflated::End,
                Mode::Bad => return Inflated::Error(self.message),
            }
        }
    }
}

// LZMA1, as liblzma's raw decoder. Input may run out inside a symbol. liblzma resumes where it was;
// this undoes the symbol and decodes it again with more input, which comes to the same, because a
// symbol does nothing visible before it's complete except the two checks kept in the same order.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LzmaStatus {
    End,
    Full,
    NeedInput,
}

const PROB_INIT: u16 = 1024;
const STATES: usize = 12;
const POS_STATES: usize = 16;
const IS_MATCH: usize = 0;
const IS_REP: usize = IS_MATCH + STATES * POS_STATES;
const IS_REP0: usize = IS_REP + STATES;
const IS_REP1: usize = IS_REP0 + STATES;
const IS_REP2: usize = IS_REP1 + STATES;
const IS_REP0_LONG: usize = IS_REP2 + STATES;
const DIST_SLOT: usize = IS_REP0_LONG + STATES * POS_STATES;
const POS_SPECIAL: usize = DIST_SLOT + 4 * 64;
const POS_ALIGN: usize = POS_SPECIAL + 115;
const MATCH_LEN: usize = POS_ALIGN + 16;
const LEN_SIZE: usize = 2 + 2 * POS_STATES * 8 + 256;
const REP_LEN: usize = MATCH_LEN + LEN_SIZE;
const LITERAL: usize = REP_LEN + LEN_SIZE;

#[derive(Clone, Copy)]
enum Pending {
    None,
    Byte(u8),
    Copy(u32),
}

struct OutOfInput;

struct LzmaDecoder {
    probs: Vec<u16>,
    undo: Vec<(u32, u16)>,
    lc: u32,
    literal_mask: u32,
    pos_mask: u32,
    next: usize,
    range: u32,
    code: u32,
    init_left: u8,
    state: usize,
    reps: [u32; 4],
    pending: Pending,
    eopm: bool,
    dict_size: usize,
    window: Vec<u8>,
    window_at: usize,
    total: u64,
    produced_now: u64,
}

fn lzma_error(message: &str) -> PyErr {
    PyErr::new("LZMAError", message)
}

impl LzmaDecoder {
    /// `lzma._decode_filter_properties` and the decoder it goes to.
    fn new(props: &[u8], start: usize) -> PyResult<LzmaDecoder> {
        let unsupported = || lzma_error("Invalid or unsupported options");
        if props.len() != 5 {
            return Err(unsupported());
        }
        let mut byte = u32::from(props[0]);
        if byte > (4 * 5 + 4) * 9 + 8 {
            return Err(unsupported());
        }
        let pb = byte / (9 * 5);
        byte -= pb * 9 * 5;
        let lp = byte / 9;
        let lc = byte - lp * 9;
        if lc + lp > 4 {
            return Err(unsupported());
        }
        let dict_size = u32_at(props, 1).max(4096) as usize;
        let dict_size = (dict_size + 15) & !15;
        let probs = vec![PROB_INIT; LITERAL + (0x300 << (lc + lp))];
        Ok(LzmaDecoder {
            probs,
            undo: Vec::with_capacity(64),
            lc,
            literal_mask: (0x100u32 << lp) - (0x100u32 >> lc),
            pos_mask: (1u32 << pb) - 1,
            next: start,
            range: u32::MAX,
            code: 0,
            init_left: 5,
            state: 0,
            reps: [0; 4],
            pending: Pending::None,
            eopm: false,
            dict_size,
            window: Vec::new(),
            window_at: 0,
            total: 0,
            produced_now: 0,
        })
    }

    #[inline]
    fn bit(&mut self, input: &[u8], at: &mut usize, index: usize) -> Result<u32, OutOfInput> {
        self.normalize(input, at)?;
        let prob = self.probs[index];
        self.undo.push((index as u32, prob));
        let bound = (self.range >> 11) * u32::from(prob);
        if self.code < bound {
            self.range = bound;
            self.probs[index] = prob + ((2048 - prob) >> 5);
            Ok(0)
        } else {
            self.range -= bound;
            self.code -= bound;
            self.probs[index] = prob - (prob >> 5);
            Ok(1)
        }
    }

    #[inline]
    fn normalize(&mut self, input: &[u8], at: &mut usize) -> Result<(), OutOfInput> {
        if self.range < (1 << 24) {
            let Some(&byte) = input.get(*at) else {
                return Err(OutOfInput);
            };
            *at += 1;
            self.range <<= 8;
            self.code = self.code << 8 | u32::from(byte);
        }
        Ok(())
    }

    fn bittree(
        &mut self,
        input: &[u8],
        at: &mut usize,
        base: usize,
        size: u32,
    ) -> Result<u32, OutOfInput> {
        let mut symbol = 1u32;
        while symbol < size {
            symbol = symbol << 1 | self.bit(input, at, base + symbol as usize)?;
        }
        Ok(symbol - size)
    }

    fn length(
        &mut self,
        input: &[u8],
        at: &mut usize,
        base: usize,
        pos_state: usize,
    ) -> Result<u32, OutOfInput> {
        if self.bit(input, at, base)? == 0 {
            let low = base + 2 + pos_state * 8;
            return Ok(2 + self.bittree(input, at, low, 8)?);
        }
        if self.bit(input, at, base + 1)? == 0 {
            let mid = base + 2 + POS_STATES * 8 + pos_state * 8;
            return Ok(2 + 8 + self.bittree(input, at, mid, 8)?);
        }
        let high = base + 2 + 2 * POS_STATES * 8;
        Ok(2 + 8 + 8 + self.bittree(input, at, high, 256)?)
    }

    fn valid_distance(&self, distance: u32) -> bool {
        self.total.min(self.dict_size as u64) > u64::from(distance)
    }

    fn get(&self, distance: u32) -> u8 {
        let distance = distance as usize;
        if self.window.len() < self.dict_size {
            self.window
                .len()
                .checked_sub(distance + 1)
                .map_or(0, |at| self.window[at])
        } else {
            self.window
                [(self.window_at + self.dict_size - 1 - distance % self.dict_size) % self.dict_size]
        }
    }

    fn put(&mut self, byte: u8, sink: &mut Sink) -> PyResult<()> {
        if self.window.len() < self.dict_size {
            if self.window.len() > MAX_MEMBER {
                return Err(memory_error());
            }
            self.window.push(byte);
        } else {
            self.window[self.window_at] = byte;
            self.window_at = (self.window_at + 1) % self.dict_size;
        }
        self.total += 1;
        self.produced_now += 1;
        sink.push(byte);
        Ok(())
    }

    /// One symbol, without writing it. Leaves what it decoded in `pending`, or returns the end of
    /// the stream or an error. On OutOfInput the caller undoes it.
    fn symbol(&mut self, input: &[u8], at: &mut usize) -> Result<PyResult<bool>, OutOfInput> {
        let data_error = || Ok(Err(lzma_error("Corrupt input data")));
        if self.eopm {
            self.normalize(input, at)?;
            return if self.code == 0 {
                Ok(Ok(true))
            } else {
                data_error()
            };
        }
        let state = self.state;
        let pos_state = (self.total & u64::from(self.pos_mask)) as usize;
        if self.bit(input, at, IS_MATCH + state * POS_STATES + pos_state)? == 0 {
            let previous = if self.total == 0 { 0 } else { self.get(0) };
            let context = ((self.total as u32) << 8).wrapping_add(u32::from(previous));
            let subcoder = 3 * ((context & self.literal_mask) << self.lc) as usize;
            let base = LITERAL + subcoder;
            let mut symbol = 1u32;
            if state < 7 {
                self.state = match state {
                    0..=3 => 0,
                    _ => state - 3,
                };
                while symbol < 0x100 {
                    symbol = symbol << 1 | self.bit(input, at, base + symbol as usize)?;
                }
            } else {
                self.state = if state <= 9 { state - 3 } else { state - 6 };
                let mut matched = u32::from(self.get(self.reps[0])) << 1;
                let mut offset = 0x100u32;
                while symbol < 0x100 {
                    let match_bit = matched & offset;
                    let index = base + (offset + match_bit + symbol) as usize;
                    let bit = self.bit(input, at, index)?;
                    if bit == 0 {
                        offset &= !match_bit;
                    } else {
                        offset &= match_bit;
                    }
                    symbol = symbol << 1 | bit;
                    matched <<= 1;
                }
            }
            self.pending = Pending::Byte(symbol as u8);
            return Ok(Ok(false));
        }
        let length;
        if self.bit(input, at, IS_REP + state)? == 0 {
            self.state = if state < 7 { 7 } else { 10 };
            self.reps = [self.reps[0], self.reps[0], self.reps[1], self.reps[2]];
            length = self.length(input, at, MATCH_LEN, pos_state)?;
            let dist_state = (length as usize - 2).min(3);
            let slot = self.bittree(input, at, DIST_SLOT + dist_state * 64, 64)?;
            let mut distance = slot;
            if slot >= 4 {
                let limit = (slot >> 1) - 1;
                distance = 2 + (slot & 1);
                if slot < 14 {
                    distance <<= limit;
                    let base = POS_SPECIAL + distance as usize - slot as usize - 1;
                    let mut symbol = 1u32;
                    for offset in 0..limit {
                        let bit = self.bit(input, at, base + symbol as usize)?;
                        symbol = symbol << 1 | bit;
                        distance = distance.wrapping_add(bit << offset);
                    }
                } else {
                    for _ in 0..limit - 4 {
                        self.normalize(input, at)?;
                        self.range >>= 1;
                        self.code = self.code.wrapping_sub(self.range);
                        let top = 0u32.wrapping_sub(self.code >> 31);
                        self.code = self.code.wrapping_add(self.range & top);
                        distance = (distance << 1).wrapping_add(top.wrapping_add(1));
                    }
                    distance <<= 4;
                    let mut symbol = 0u32;
                    let mut offset = 1u32;
                    while offset < 16 {
                        let index = POS_ALIGN + (offset + symbol) as usize;
                        if self.bit(input, at, index)? == 1 {
                            symbol += offset;
                        }
                        offset <<= 1;
                    }
                    distance = distance.wrapping_add(symbol);
                    if distance == u32::MAX {
                        self.eopm = true;
                        return Ok(Ok(false));
                    }
                }
            }
            self.reps[0] = distance;
            if !self.valid_distance(distance) {
                return data_error();
            }
        } else {
            if !self.valid_distance(0) {
                return data_error();
            }
            if self.bit(input, at, IS_REP0 + state)? == 0 {
                let index = IS_REP0_LONG + state * POS_STATES + pos_state;
                if self.bit(input, at, index)? == 0 {
                    self.state = if state < 7 { 9 } else { 11 };
                    self.pending = Pending::Byte(self.get(self.reps[0]));
                    return Ok(Ok(false));
                }
            } else if self.bit(input, at, IS_REP1 + state)? == 0 {
                self.reps.swap(0, 1);
            } else if self.bit(input, at, IS_REP2 + state)? == 0 {
                self.reps = [self.reps[2], self.reps[0], self.reps[1], self.reps[3]];
            } else {
                self.reps = [self.reps[3], self.reps[0], self.reps[1], self.reps[2]];
            }
            self.state = if state < 7 { 8 } else { 11 };
            length = self.length(input, at, REP_LEN, pos_state)?;
        }
        self.pending = Pending::Copy(length);
        Ok(Ok(false))
    }

    /// `LZMADecompressor.decompress(data, limit)`, where `input` ends where the given data ends.
    /// `used` becomes how far liblzma would have used it.
    fn decode(
        &mut self,
        input: &[u8],
        used: &mut usize,
        limit: u64,
        sink: &mut Sink,
    ) -> PyResult<LzmaStatus> {
        self.produced_now = 0;
        while self.init_left > 0 {
            let Some(&byte) = input.get(self.next) else {
                *used = input.len();
                return Ok(LzmaStatus::NeedInput);
            };
            if self.init_left == 5 && byte != 0 {
                return Err(lzma_error("Corrupt input data"));
            }
            self.code = self.code << 8 | u32::from(byte);
            self.next += 1;
            self.init_left -= 1;
        }
        loop {
            *used = self.next;
            match self.pending {
                Pending::None => {}
                Pending::Byte(byte) => {
                    if self.produced_now == limit {
                        return Ok(LzmaStatus::Full);
                    }
                    self.put(byte, sink)?;
                    self.pending = Pending::None;
                }
                Pending::Copy(length) => {
                    let room = limit - self.produced_now;
                    let copy = u64::from(length).min(room) as u32;
                    for _ in 0..copy {
                        let byte = self.get(self.reps[0]);
                        self.put(byte, sink)?;
                    }
                    if copy < length {
                        self.pending = Pending::Copy(length - copy);
                        return Ok(LzmaStatus::Full);
                    }
                    self.pending = Pending::None;
                }
            }
            if sink.overflowed() {
                return Ok(LzmaStatus::Full);
            }
            self.undo.clear();
            let saved = (self.next, self.range, self.code, self.state, self.reps);
            let mut at = self.next;
            match self.symbol(input, &mut at) {
                Ok(Ok(true)) => return Ok(LzmaStatus::End),
                Ok(Ok(false)) => self.next = at,
                Ok(Err(error)) => return Err(error),
                Err(OutOfInput) => {
                    while let Some((index, prob)) = self.undo.pop() {
                        self.probs[index as usize] = prob;
                    }
                    (self.next, self.range, self.code, self.state, self.reps) = saved;
                    *used = input.len();
                    return Ok(LzmaStatus::NeedInput);
                }
            }
        }
    }
}

/// `zlib.decompress` when `whole`, and otherwise a `decompressobj()` fed everything, which keeps what
/// a truncated stream gave. A zlib error is Python's kind and message, as `read_member` reports them.
pub(crate) fn zlib_decompress(data: &[u8], whole: bool, limit: usize) -> PyResult<Vec<u8>> {
    let zlib_error = |message: &str| {
        PyErr::new(
            "error",
            format!("Error -3 while decompressing data: {message}"),
        )
    };
    let truncated = || {
        if whole {
            Err(PyErr::new(
                "error",
                "Error -5 while decompressing data: incomplete or truncated stream",
            ))
        } else {
            Ok(Vec::new())
        }
    };
    if data.len() < 2 {
        return truncated();
    }
    let (cmf, flags) = (data[0], data[1]);
    if (u32::from(cmf) * 256 + u32::from(flags)) % 31 != 0 {
        return Err(zlib_error("incorrect header check"));
    }
    if cmf & 0x0F != 8 {
        return Err(zlib_error("unknown compression method"));
    }
    if (cmf >> 4) + 8 > 15 {
        return Err(zlib_error("invalid window size"));
    }
    if flags & 0x20 != 0 {
        return Err(if whole {
            PyErr::new("error", "Error 2 while decompressing data: need dictionary")
        } else {
            PyErr::new("error", "Error 2 while decompressing data")
        });
    }
    let mut inflate = Inflate::new();
    let mut sink = Sink::new(limit as i128 + 1);
    let mut at = 2;
    loop {
        match inflate.run(data, &mut at, limit as u64 + 1, &mut sink) {
            Inflated::End => break,
            Inflated::Error(message) => return Err(zlib_error(message)),
            Inflated::Partial => {
                if sink.kept.len() > limit {
                    return Err(memory_error());
                }
                if at >= data.len() {
                    return if whole { truncated() } else { Ok(sink.kept) };
                }
            }
        }
    }
    if sink.kept.len() > limit {
        return Err(memory_error());
    }
    let out = sink.kept;
    let mut adler_a: u32 = 1;
    let mut adler_b: u32 = 0;
    for chunk in out.chunks(5552) {
        for &byte in chunk {
            adler_a += u32::from(byte);
            adler_b += adler_a;
        }
        adler_a %= 65521;
        adler_b %= 65521;
    }
    let Some(tail) = data.get(at..at + 4) else {
        return if whole { truncated() } else { Ok(out) };
    };
    if u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]) != (adler_b << 16) | adler_a {
        return Err(zlib_error("incorrect data check"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO_DEFLATE: &[u8] = b"\xcb\x48\xcd\xc9\xc9\x07\x00";
    const HELLO_LZMA: &[u8] = b"\x09\x04\x05\x00\x5d\x00\x00\x01\x00\x00\x34\x19\x49\xee\x8e\x68\
        \x21\xff\xff\xff\xb9\xe0\x00\x00";
    const HELLO_BZIP2: &[u8] = b"BZh91AY&SY\x191e=\x00\x00\x00\x81\x00\x02D\xa0\x00!\x9ah3M\x073\
        \x8b\xb9\"\x9c(H\x0c\x98\xb2\x9e\x80";

    struct Member<'a> {
        name: &'a [u8],
        method: u16,
        flags: u16,
        comp: &'a [u8],
        crc: u32,
        size: u32,
    }

    fn member<'a>(name: &'a [u8], method: u16, comp: &'a [u8], data: &[u8]) -> Member<'a> {
        Member {
            name,
            method,
            flags: 0,
            comp,
            crc: crc32fast::hash(data),
            size: data.len() as u32,
        }
    }

    fn build(members: &[Member<'_>]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut directory = Vec::new();
        for member in members {
            let offset = body.len() as u32;
            let name_len = member.name.len() as u16;
            let comp_len = member.comp.len() as u32;
            let shared = |out: &mut Vec<u8>| {
                out.extend_from_slice(&member.flags.to_le_bytes());
                out.extend_from_slice(&member.method.to_le_bytes());
                out.extend_from_slice(&[0; 4]);
                out.extend_from_slice(&member.crc.to_le_bytes());
                out.extend_from_slice(&comp_len.to_le_bytes());
                out.extend_from_slice(&member.size.to_le_bytes());
                out.extend_from_slice(&name_len.to_le_bytes());
                out.extend_from_slice(&[0; 2]);
            };
            body.extend_from_slice(b"PK\x03\x04\x14\x00");
            shared(&mut body);
            body.extend_from_slice(member.name);
            body.extend_from_slice(member.comp);
            directory.extend_from_slice(b"PK\x01\x02\x14\x03\x14\x00");
            shared(&mut directory);
            directory.extend_from_slice(&[0; 10]);
            directory.extend_from_slice(&offset.to_le_bytes());
            directory.extend_from_slice(member.name);
        }
        let start = body.len() as u32;
        let size = directory.len() as u32;
        body.append(&mut directory);
        body.extend_from_slice(b"PK\x05\x06\x00\x00\x00\x00");
        body.extend_from_slice(&(members.len() as u16).to_le_bytes());
        body.extend_from_slice(&(members.len() as u16).to_le_bytes());
        body.extend_from_slice(&size.to_le_bytes());
        body.extend_from_slice(&start.to_le_bytes());
        body.extend_from_slice(&[0; 2]);
        body
    }

    fn error<T: std::fmt::Debug>(result: PyResult<T>) -> (String, String) {
        let error = result.expect_err("an exception");
        (error.kind, error.message)
    }

    fn expected(kind: &str, message: &str) -> (String, String) {
        (kind.to_owned(), message.to_owned())
    }

    #[test]
    fn duplicates_methods_and_names_are_pythons() {
        let data = build(&[
            member(b"d", STORED, b"first", b"first"),
            member(b"d\0x", STORED, b"second", b"second"),
            member(b"l", LZMA, HELLO_LZMA, b"hello"),
            member(b"b", BZIP2, HELLO_BZIP2, b"hello"),
            member(b"z", DEFLATED, HELLO_DEFLATE, b"hello"),
        ]);
        let zip = ZipFile::new(&data).expect("opens");
        assert_eq!(zip.namelist(), ["d", "d", "l", "b", "z"]);
        assert!(zip.contains("d") && !zip.contains("d\0x"));
        assert_eq!(zip.read("d").expect("reads"), b"second");
        assert_eq!(zip.read_member(0, None).expect("reads"), b"first");
        for name in ["l", "b", "z"] {
            assert_eq!(zip.read(name).expect("reads"), b"hello");
        }
        assert_eq!(
            error(zip.read("it's")),
            expected(
                "KeyError",
                "'There is no item named \"it\\'s\" in the archive'"
            )
        );
    }

    #[test]
    fn a_read_sees_what_its_chunk_reaches() {
        let bad_crc = |comp: &'static [u8]| {
            let mut one = member(b"a", STORED, comp, comp);
            one.crc = 1;
            build(&[one])
        };
        // all of it is in the first chunk, so read(2) checks the CRC
        let short = bad_crc(b"hello");
        let zip = ZipFile::new(&short).expect("opens");
        let crc_error = expected("BadZipFile", "Bad CRC-32 for file 'a'");
        assert_eq!(error(zip.open_read("a", Some(2))), crc_error);
        // this one isn't, so only the whole read does
        let long = bad_crc(&[b'x'; 5000]);
        let zip = ZipFile::new(&long).expect("opens");
        assert_eq!(zip.open_read("a", Some(8)).expect("reads"), b"xxxxxxxx");
        assert_eq!(error(zip.read("a")), crc_error);
        // a stored block of eight bytes and a bad block: read(8) decompresses on past what it needs
        let comp = b"\x00\x08\x00\xf7\xffyyyyyyyy\x01\x05\x00\x05\x00";
        let mut one = member(b"a", DEFLATED, comp, b"yyyyyyyy");
        one.size = 100;
        let data = build(&[one]);
        let zip = ZipFile::new(&data).expect("opens");
        assert_eq!(
            error(zip.open_read("a", Some(8))),
            expected(
                "error",
                "Error -3 while decompressing data: invalid stored block lengths"
            )
        );
    }

    #[test]
    fn open_raises_what_python_raises() {
        let mut encrypted = member(b"e", STORED, b"", b"");
        encrypted.flags = FLAG_ENCRYPTED;
        let mut patched = member(b"f", STORED, b"", b"");
        patched.flags = FLAG_PATCH;
        let data = build(&[encrypted, member(b"m", 9, b"", b""), patched]);
        let zip = ZipFile::new(&data).expect("opens");
        assert_eq!(
            error(zip.read("e")),
            expected(
                "RuntimeError",
                "File 'e' is encrypted, password required for extraction"
            )
        );
        assert_eq!(
            error(zip.read("m")),
            expected(
                "NotImplementedError",
                "That compression method is not supported"
            )
        );
        assert_eq!(
            error(zip.read("f")),
            expected(
                "NotImplementedError",
                "compressed patched data (flag bit 5)"
            )
        );
    }

    #[test]
    fn the_constructor_and_is_zipfile_are_pythons() {
        let not_zip = expected("BadZipFile", "File is not a zip file");
        assert!(!is_zipfile(b""));
        assert_eq!(error(ZipFile::new(b"")), not_zip);
        let mut empty = b"PK\x05\x06".to_vec();
        empty.extend_from_slice(&[0; 18]);
        assert!(is_zipfile(&empty));
        assert!(ZipFile::new(&empty).expect("opens").namelist().is_empty());
        // a central directory bigger than what's before it
        let mut before_start = b"PK\x05\x06".to_vec();
        before_start.extend_from_slice(&[0; 8]);
        before_start.extend_from_slice(&46u32.to_le_bytes());
        before_start.extend_from_slice(&5u32.to_le_bytes());
        before_start.extend_from_slice(&[0; 2]);
        assert_eq!(
            error(check_zipfile(&before_start)),
            expected("ValueError", "negative seek value -46")
        );
        assert_eq!(
            error(ZipFile::new(&before_start)),
            expected("BadZipFile", "Bad offset for central directory")
        );
        let mut bad_name = member(b"\xff", STORED, b"", b"");
        bad_name.flags = FLAG_UTF8;
        assert_eq!(
            error(ZipFile::new(&build(&[bad_name]))),
            expected(
                "UnicodeDecodeError",
                "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"
            )
        );
    }
}
