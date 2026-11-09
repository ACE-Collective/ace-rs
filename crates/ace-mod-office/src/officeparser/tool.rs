//! officeparser3 at `af70dd43` (`unixfreak0037/officeparser3`, the commit ace3's image installs), run
//! as ace3 runs it: every print and check option, then `--extract-streams --extract-ole-streams
//! --extract-macros --extract-unknown-sectors --create-manifest` into an output directory.
//!
//! This is a port of its own compound file reader rather than olefile's, because what it writes
//! for a damaged file is decided by how it reads one: it follows the header's FAT and DIFAT itself,
//! names streams by their index in the directory, raises `NameError` on a chain that loops, stops
//! where Python raises, and loops for ever in its checks on a FAT that goes in a circle, which ace3
//! ends at its timeout. Each of those decides what the manifest lists.
//!
//! The output directory is held in memory: a name officeparser3 would write elsewhere, through
//! `..`, writes nothing here and goes on, and one it can't open there raises, as on ace3's disk. The
//! manifest is written as Python's buffered file is: at the end, over whatever has the name by
//! then, and not at all when the run is killed.
//!
//! officeparser3 is MIT-licensed, as its package's metadata in ace3's image says.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

use ace_pycompat::pystr;

const OLE_SIGNATURE: &[u8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";
const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
const FREESECT: u32 = 0xFFFF_FFFF;
const STGTY_INVALID: i8 = 0;
const STGTY_STREAM: i8 = 2;

/// The largest `read(n)` Python grants on ace3's dev container: past it, the bytes object for `n`
/// can't be allocated and it raises `MemoryError`; at `2**63` it raises `OverflowError`.
const MAX_READ: u128 = 1 << 34;
/// Past this many FAT entries the reader would hold gigabytes of Python ints, which ace3's process
/// doesn't survive; here it raises `MemoryError`.
const MAX_FAT: usize = 1 << 26;
/// Past this many bytes of streams read, each chain counted once however many entries name it,
/// officeparser3 is still reading when ace3's 90 seconds run out; here the run stops as if killed.
pub const MAX_WRITTEN: usize = 256 * 1024 * 1024;
/// The smallest shift whose `2 ** shift` has more than 4,300 digits, Python's limit on printing an
/// int.
const MAX_PRINTED_SHIFT: u16 = 14_285;
/// ace3's file system's `NAME_MAX`.
const NAME_MAX: usize = 255;

/// How the run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// It got to the end.
    Finished,
    /// Python raised this, and the interpreter flushed the manifest on its way out.
    Raised(String),
    /// `sys.exit(0)`, which officeparser3 calls on an unknown REFERENCE record.
    Exited,
    /// It wouldn't have ended: ace3 kills it at its timeout, and the manifest's buffer is lost.
    Killed,
}

/// What a run leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub end: End,
    /// Whether the manifest was created: not when reading the file raised first.
    pub manifest: bool,
    /// The output directory's files, by name. Files with the same bytes from the same chain share
    /// them.
    pub files: BTreeMap<String, Rc<Vec<u8>>>,
}

#[derive(Debug)]
enum Stop {
    Raise(String),
    Exit,
    Hang,
}

type R<T> = Result<T, Stop>;

fn raise<T>(message: impl Into<String>) -> R<T> {
    Err(Stop::Raise(message.into()))
}

/// `struct.unpack('<{n}L', data)`.
fn unpack_u32s(data: &[u8], n: u128) -> R<Vec<u32>> {
    if data.len() as u128 != n * 4 {
        return raise(format!(
            "struct.error: unpack requires a buffer of {} bytes",
            n * 4
        ));
    }
    Ok(data
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .collect())
}

fn u16_at(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// `unpack('<H', data[0:2])` and the like on a slice that may be short.
fn unpack_u16(data: &[u8]) -> R<u16> {
    if data.len() != 2 {
        return raise("struct.error: unpack requires a buffer of 2 bytes");
    }
    Ok(u16_at(data, 0))
}

fn unpack_u32(data: &[u8]) -> R<u32> {
    if data.len() != 4 {
        return raise("struct.error: unpack requires a buffer of 4 bytes");
    }
    Ok(u32_at(data, 0))
}

struct Header {
    sector_shift: u16,
    mini_sector_shift: u16,
    sect_dir_start: u32,
    mini_sector_cutoff: u32,
    sect_mini_fat_start: u32,
    sect_dif_start: u32,
    sect_fat: Vec<u32>,
}

impl Header {
    fn new(data: &[u8]) -> R<Header> {
        if data.len() != 512 {
            return raise("struct.error: unpack requires a buffer of 512 bytes");
        }
        Ok(Header {
            sector_shift: u16_at(data, 30),
            mini_sector_shift: u16_at(data, 32),
            sect_dir_start: u32_at(data, 48),
            mini_sector_cutoff: u32_at(data, 56),
            sect_mini_fat_start: u32_at(data, 60),
            sect_dif_start: u32_at(data, 68),
            sect_fat: (0..109).map(|i| u32_at(data, 76 + i * 4)).collect(),
        })
    }
}

/// `Directory`: the fields officeparser3 reads.
struct Directory {
    index: usize,
    /// The name's bytes but NUL, each a character, as `chr(x)` of each makes them.
    name: String,
    /// `_mse`, a signed byte.
    mse: i8,
    sect_start: u32,
    ul_size: u32,
}

impl Directory {
    fn new(chunk: &[u8], index: usize) -> Directory {
        let cb = usize::from(u16_at(chunk, 64));
        let name = chunk[..cb.min(64)]
            .iter()
            .filter(|&&b| b != 0)
            .map(|&b| char::from(b))
            .collect();
        Directory {
            index,
            name,
            mse: chunk[66] as i8,
            sect_start: u32_at(chunk, 116),
            ul_size: u32_at(chunk, 120),
        }
    }
}

/// A sector size, `2 ** shift`, which can be larger than any integer here.
#[derive(Clone, Copy)]
struct Size(Option<u128>);

impl Size {
    fn pow2(shift: u16) -> Size {
        Size((shift < 127).then(|| 1u128 << shift))
    }
}

/// A stream's start, size and whether it's in the ministream, which decide its bytes.
type StreamKey = (u32, u32, bool);

/// `CompoundBinaryFile`.
struct Doc<'a> {
    data: &'a [u8],
    header: Header,
    sector_size: Size,
    mini_sector_size: Size,
    fat: Vec<u32>,
    directory: Vec<Directory>,
    /// `None` when the root entry's chain is ENDOFCHAIN and the attribute is never set.
    ministream: Option<Vec<u8>>,
    minifat: Vec<u32>,
    /// Streams read, by start, size and whether in the ministream: the same entry read again, or
    /// another naming the same chain, gives the same bytes.
    streams: RefCell<HashMap<StreamKey, Rc<Vec<u8>>>>,
    read: Cell<usize>,
}

impl<'a> Doc<'a> {
    fn new(data: &'a [u8]) -> R<Doc<'a>> {
        let header = Header::new(&data[..data.len().min(512)])?;
        let mut doc = Doc {
            data,
            sector_size: Size::pow2(header.sector_shift),
            mini_sector_size: Size::pow2(header.mini_sector_shift),
            header,
            fat: Vec::new(),
            directory: Vec::new(),
            ministream: None,
            minifat: Vec::new(),
            streams: RefCell::new(HashMap::new()),
            read: Cell::new(0),
        };
        // the debug lines print both sizes, and Python won't turn an int of more than 4,300 digits
        // into text
        if doc.header.sector_shift >= MAX_PRINTED_SHIFT
            || doc.header.mini_sector_shift >= MAX_PRINTED_SHIFT
        {
            return raise(
                "ValueError: Exceeds the limit (4300 digits) for integer string conversion",
            );
        }
        let ss = doc.sector_size;
        let per_sector = ss.0.map_or(u128::MAX, |s| s / 4);
        let mut fat_sectors: Vec<u32> = doc
            .header
            .sect_fat
            .iter()
            .copied()
            .filter(|&s| s != FREESECT)
            .collect();

        // the DIF sectors, the last value of each pointing on
        let mut sector = doc.header.sect_dif_start;
        let mut seen = HashSet::from([sector]);
        while sector != FREESECT && sector != ENDOFCHAIN {
            let raw = doc.read_sector(sector)?;
            let mut values = unpack_u32s(raw, per_sector)?;
            let Some(next) = values.pop() else {
                return raise("IndexError: pop from empty list");
            };
            fat_sectors.extend(values.into_iter().filter(|&v| v != FREESECT));
            if !seen.insert(next) {
                break;
            }
            sector = next;
        }

        for fat_sect in fat_sectors {
            let raw = doc.read_sector(fat_sect)?;
            if ss.0 != Some(raw.len() as u128) {
                // "broken FAT (invalid sector size)", logged
                continue;
            }
            doc.fat.extend(unpack_u32s(raw, per_sector)?);
            if doc.fat.len() > MAX_FAT {
                return raise("MemoryError");
            }
        }

        let buffer = doc.read_chain(doc.header.sect_dir_start)?;
        if buffer.len() % 128 != 0 {
            return raise("struct.error: unpack requires a buffer of a multiple of 128 bytes");
        }
        doc.directory = buffer
            .as_chunks::<128>()
            .0
            .iter()
            .enumerate()
            .map(|(i, chunk)| Directory::new(chunk, i))
            .collect();

        let Some(root) = doc.directory.first() else {
            return raise("IndexError: list index out of range");
        };
        if root.sect_start != ENDOFCHAIN {
            let (start, size) = (root.sect_start, root.ul_size as usize);
            let mut ministream = doc.read_chain(start)?;
            ministream.truncate(size);
            doc.ministream = Some(ministream);
            let raw = doc.read_chain(doc.header.sect_mini_fat_start)?;
            if let Some(ss) = ss.0 {
                for chunk in raw.chunks(ss as usize) {
                    if chunk.len() as u128 != ss {
                        // "encountered EOF while parsing minifat", and the next read is empty
                        break;
                    }
                    doc.minifat.extend(unpack_u32s(chunk, per_sector)?);
                }
            }
        }
        Ok(doc)
    }

    /// `read_sector`: `seek(512 + size * sector)` and `read(size)`.
    fn read_sector(&self, sector: u32) -> R<&'a [u8]> {
        let Some(size) = self.sector_size.0 else {
            return raise("OverflowError: cannot fit 'int' into an index-sized integer");
        };
        let offset = 512 + size * u128::from(sector);
        if offset > i64::MAX as u128 {
            return raise("ValueError: cannot fit 'int' into an offset-sized integer");
        }
        if size >= 1 << 63 {
            return raise("OverflowError: cannot fit 'int' into an index-sized integer");
        }
        if size > MAX_READ {
            return raise("MemoryError");
        }
        let len = self.data.len() as u128;
        let start = offset.min(len) as usize;
        let end = (offset + size).min(len) as usize;
        Ok(&self.data[start..end])
    }

    fn read_fat(&self, sector: u32) -> R<u32> {
        match self.fat.get(sector as usize) {
            Some(&v) => Ok(v),
            None => raise("IndexError: list index out of range"),
        }
    }

    fn read_mini_sector(&self, sector: u32) -> R<&[u8]> {
        let Some(ministream) = &self.ministream else {
            return raise(
                "AttributeError: 'CompoundBinaryFile' object has no attribute 'ministream'",
            );
        };
        let Some(size) = self.mini_sector_size.0 else {
            // `ministream[0:huge]` is all of it, and any other offset is past its end
            return Ok(if sector == 0 { ministream } else { &[] });
        };
        let len = ministream.len() as u128;
        let offset = u128::from(sector) * size;
        let start = offset.min(len) as usize;
        let end = (offset + size).min(len) as usize;
        Ok(&ministream[start..end])
    }

    fn read_mini_fat(&self, sector: u32) -> R<u32> {
        match self.minifat.get(sector as usize) {
            Some(&v) => Ok(v),
            None => raise("IndexError: list index out of range"),
        }
    }

    /// `__impl_read_chain`: a loop raises `NameError`, as its message names a variable that isn't
    /// there.
    fn chain(&self, start: u32, mini: bool) -> R<Vec<u8>> {
        let mut sector = start;
        let mut check = HashSet::from([sector]);
        let mut buffer = Vec::new();
        while sector != ENDOFCHAIN {
            let next = if mini {
                buffer.extend_from_slice(self.read_mini_sector(sector)?);
                self.read_mini_fat(sector)?
            } else {
                buffer.extend_from_slice(self.read_sector(sector)?);
                self.read_fat(sector)?
            };
            if !check.insert(next) {
                return raise("NameError: name 'sector_start' is not defined");
            }
            sector = next;
        }
        Ok(buffer)
    }

    fn read_chain(&self, start: u32) -> R<Vec<u8>> {
        self.chain(start, false)
    }

    fn get_stream(&self, index: usize) -> R<Rc<Vec<u8>>> {
        let d = &self.directory[index];
        let mini = d.ul_size < self.header.mini_sector_cutoff;
        let key = (d.sect_start, d.ul_size, mini);
        if let Some(data) = self.streams.borrow().get(&key) {
            return Ok(data.clone());
        }
        let mut data = if mini {
            self.chain(d.sect_start, true)?
        } else {
            self.read_chain(d.sect_start)?
        };
        data.truncate(d.ul_size as usize);
        self.read.set(self.read.get() + data.len());
        if self.read.get() > MAX_WRITTEN {
            return Err(Stop::Hang);
        }
        let data = Rc::new(data);
        self.streams.borrow_mut().insert(key, data.clone());
        Ok(data)
    }

    fn find_stream_by_name(&self, name: &str) -> Option<usize> {
        self.directory
            .iter()
            .find(|d| d.name == name)
            .map(|d| d.index)
    }
}

/// `decompress_stream`, MS-OVBA 2.4.1 as officeparser3 has it: `None` for a bad signature byte.
fn decompress_stream(container: &[u8]) -> R<Option<Vec<u8>>> {
    let Some(&signature) = container.first() else {
        return raise("IndexError: index out of range");
    };
    if signature != 0x01 {
        return Ok(None);
    }
    let mut out: Vec<u8> = Vec::new();
    let mut current = 1usize;
    while current < container.len() {
        let header = unpack_u16(&container[current..(current + 2).min(container.len())])?;
        let chunk_size = usize::from(header & 0x0FFF) + 3;
        let compressed = header & 0x8000 != 0;
        let end = container.len().min(current + chunk_size);
        current += 2;
        if !compressed {
            let from = current.min(container.len());
            out.extend_from_slice(&container[from..(current + 4096).min(container.len())]);
            current += 4096;
            continue;
        }
        let chunk_start = out.len();
        while current < end {
            let flags = container[current];
            current += 1;
            for bit in 0..8 {
                if current >= end {
                    break;
                }
                if flags & (1 << bit) == 0 {
                    out.push(container[current]);
                    current += 1;
                    continue;
                }
                let token = unpack_u16(&container[current..(current + 2).min(container.len())])?;
                let difference = out.len() - chunk_start;
                if difference == 0 {
                    return raise("ValueError: math domain error");
                }
                // int(ceil(log(difference, 2))), in doubles as CPython computes it
                let bit_count = ((difference as f64).ln() / 2f64.ln()).ceil() as i64;
                let bit_count = bit_count.max(4);
                let length_mask: i64 = 0xFFFF >> bit_count.min(63);
                let length = i64::from(token) & length_mask;
                let length = length + 3;
                let temp1 = i64::from(token) & !length_mask;
                let temp2 = 16 - bit_count;
                if temp2 < 0 {
                    return raise("ValueError: negative shift count");
                }
                let offset = (temp1 >> temp2) + 1;
                let copy_source = out.len() as i64 - offset;
                for index in copy_source..copy_source + length {
                    let len = out.len() as i64;
                    // a negative index counts from the end, as Python's does
                    let at = if index < 0 { len + index } else { index };
                    if at < 0 || at >= len {
                        return raise("IndexError: index out of range");
                    }
                    out.push(out[at as usize]);
                }
                current += 2;
            }
        }
    }
    Ok(Some(out))
}

/// Where `open(os.path.join(output_dir, name), 'wb')` writes.
enum Opened {
    /// A file in the output directory, by name.
    Here(String),
    /// Somewhere outside it, through `..`.
    Elsewhere,
}

/// `os.path.join(output_dir, name)` opened for writing, as the kernel walks it: only the output
/// directory and the directories above it are known to exist.
fn open_for_write(files: &BTreeMap<String, Rc<Vec<u8>>>, name: &str) -> R<Opened> {
    if name.contains('\0') {
        return raise("ValueError: embedded null byte");
    }
    #[derive(PartialEq)]
    enum At {
        Here,
        Above,
        Root,
    }
    let mut at = if name.starts_with('/') {
        At::Root
    } else {
        At::Here
    };
    let components: Vec<&str> = name.split('/').collect();
    let (last, dirs) = components.split_last().expect("split gives one");
    for &component in dirs {
        if component.len() > NAME_MAX {
            return raise("OSError: [Errno 36] File name too long");
        }
        match component {
            "" | "." => {}
            ".." => {
                if at == At::Here {
                    at = At::Above;
                }
            }
            other => {
                if at == At::Here && files.contains_key(other) {
                    return raise("NotADirectoryError: [Errno 20] Not a directory");
                }
                return raise("FileNotFoundError: [Errno 2] No such file or directory");
            }
        }
    }
    match *last {
        "" | "." | ".." => raise("IsADirectoryError: [Errno 21] Is a directory"),
        name if name.len() > NAME_MAX => raise("OSError: [Errno 36] File name too long"),
        name => match at {
            At::Here => Ok(Opened::Here(name.to_owned())),
            At::Above => Ok(Opened::Elsewhere),
            At::Root => raise("PermissionError: [Errno 13] Permission denied"),
        },
    }
}

/// `os.path.exists(os.path.join(output_dir, name))`, as far as this knows.
fn exists(files: &BTreeMap<String, Rc<Vec<u8>>>, name: &str) -> bool {
    !name.contains('/') && files.contains_key(name)
}

fn basename(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

/// The run's state: the output directory and the manifest's buffer.
struct Out {
    files: BTreeMap<String, Rc<Vec<u8>>>,
    manifest: String,
}

impl Out {
    /// `open(join(output_dir, name), 'wb')`: creates the file, empty, where it's in the directory.
    fn create(&mut self, name: &str) -> R<Option<String>> {
        match open_for_write(&self.files, name)? {
            Opened::Here(file) => {
                self.files.insert(file.clone(), Rc::default());
                Ok(Some(file))
            }
            Opened::Elsewhere => Ok(None),
        }
    }

    fn write(&mut self, file: &Option<String>, data: Rc<Vec<u8>>) {
        if let Some(file) = file {
            self.files.insert(file.clone(), data);
        }
    }

    fn list(&mut self, name: &str) {
        self.manifest.push_str(basename(name));
        self.manifest.push('\n');
    }

    /// The manifest's buffer, written at its start over what has the name now.
    fn flush(&mut self) {
        let text = self.manifest.as_bytes();
        let file = Rc::make_mut(self.files.entry("manifest".to_owned()).or_default());
        if file.len() < text.len() {
            file.resize(text.len(), 0);
        }
        file[..text.len()].copy_from_slice(text);
    }
}

/// Runs officeparser3 on `data` with ace3's options.
pub fn run(data: &[u8]) -> Run {
    let doc = match Doc::new(data) {
        Ok(doc) => doc,
        Err(stop) => {
            let end = match stop {
                Stop::Raise(message) => End::Raised(message),
                Stop::Exit => End::Exited,
                Stop::Hang => End::Killed,
            };
            return Run {
                end,
                manifest: false,
                files: BTreeMap::new(),
            };
        }
    };
    let mut out = Out {
        files: BTreeMap::from([("manifest".to_owned(), Rc::default())]),
        manifest: String::new(),
    };
    let end = match main(&doc, &mut out) {
        Ok(()) => End::Finished,
        Err(Stop::Raise(message)) => End::Raised(message),
        Err(Stop::Exit) => End::Exited,
        Err(Stop::Hang) => End::Killed,
    };
    if end != End::Killed {
        out.flush();
    }
    Run {
        end,
        manifest: true,
        files: out.files,
    }
}

fn main(doc: &Doc<'_>, out: &mut Out) -> R<()> {
    checks(doc)?;
    extract_ole_streams(doc, out)?;
    extract_streams(doc, out)?;
    extract_macros(doc, out)?;
    extract_unknown_sectors(doc, out)
}

/// `--check-stream-continuity` and `--check-orphaned-chains`, which can only raise or loop for
/// ever; the print options and `--check-fat` can neither.
fn checks(doc: &Doc<'_>) -> R<()> {
    let fat_len = doc.fat.len();
    // a walk that comes back to a sector it has seen never ends
    let walk = |start: u32, mark: bool| -> R<()> {
        let mut index = start;
        let mut seen = HashSet::new();
        while index != ENDOFCHAIN {
            if mark && index as usize >= fat_len {
                return raise("IndexError: list assignment index out of range");
            }
            if !seen.insert(index) {
                return Err(Stop::Hang);
            }
            index = doc.read_fat(index)?;
        }
        Ok(())
    };
    for d in &doc.directory[1..] {
        if d.mse == STGTY_INVALID || d.ul_size < doc.header.mini_sector_cutoff {
            continue;
        }
        if d.sect_start != ENDOFCHAIN {
            // check_stream_cont reads the FAT from the start, and stops only at ENDOFCHAIN
            let mut current = d.sect_start;
            let mut seen = HashSet::new();
            loop {
                if !seen.insert(current) {
                    return Err(Stop::Hang);
                }
                let next = doc.read_fat(current)?;
                if next == ENDOFCHAIN {
                    break;
                }
                current = next;
            }
        }
    }
    walk(doc.header.sect_dir_start, true)?;
    walk(doc.header.sect_mini_fat_start, true)?;
    for &index in &doc.header.sect_fat {
        if index != FREESECT && index as usize >= fat_len {
            return raise("IndexError: list assignment index out of range");
        }
    }
    for d in &doc.directory {
        if d.mse == STGTY_INVALID {
            continue;
        }
        if d.index > 0 && d.ul_size < doc.header.mini_sector_cutoff {
            continue;
        }
        walk(d.sect_start, true)?;
    }
    Ok(())
}

/// `--extract-ole-streams`: each `\x01Ole10Native` stream's file, by the name it carries.
fn extract_ole_streams(doc: &Doc<'_>, out: &mut Out) -> R<()> {
    for d in &doc.directory {
        if d.name != "\u{1}Ole10Native" {
            continue;
        }
        let stream = doc.get_stream(d.index)?;
        let mut data: &[u8] = &stream;
        unpack_u32(&data[..data.len().min(4)])?;
        data = &data[data.len().min(4)..];
        unpack_u16(&data[..data.len().min(2)])?;
        data = &data[data.len().min(2)..];
        let cstring = |data: &mut &[u8]| -> String {
            let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
            let text = data[..end].iter().map(|&b| char::from(b)).collect();
            *data = &data[(end + 1).min(data.len())..];
            text
        };
        let filename = cstring(&mut data);
        let _src_path = cstring(&mut data);
        for _ in 0..2 {
            unpack_u32(&data[..data.len().min(4)])?;
            data = &data[data.len().min(4)..];
        }
        let _dst_path = cstring(&mut data);
        let actual_size = unpack_u32(&data[..data.len().min(4)])? as usize;
        data = &data[data.len().min(4)..];
        let file = out.create(&filename)?;
        out.write(&file, Rc::new(data[..actual_size.min(data.len())].to_vec()));
        out.list(&filename);
    }
    Ok(())
}

/// `--extract-streams`: every stream, as `stream_<index>_<n>.dat`.
fn extract_streams(doc: &Doc<'_>, out: &mut Out) -> R<()> {
    for d in &doc.directory {
        if d.mse != STGTY_STREAM {
            continue;
        }
        let mut i = 0;
        let name = loop {
            let name = format!("stream_{}_{i}.dat", d.index);
            if !exists(&out.files, &name) {
                break name;
            }
            i += 1;
        };
        // the file is opened before the stream is read
        let file = out.create(&name)?;
        let stream = doc.get_stream(d.index)?;
        out.write(&file, stream);
        out.list(&name);
    }
    Ok(())
}

/// A `BytesIO` over the decompressed dir stream.
struct Reader {
    data: Vec<u8>,
    at: usize,
}

impl Reader {
    fn read(&mut self, n: usize) -> &[u8] {
        let start = self.at.min(self.data.len());
        let end = self.at.saturating_add(n).min(self.data.len());
        self.at = end.max(start);
        &self.data[start..end]
    }
    fn u16(&mut self) -> R<u16> {
        unpack_u16(self.read(2))
    }
    fn u32(&mut self) -> R<u32> {
        unpack_u32(self.read(4))
    }
    fn skip(&mut self, n: u32) {
        self.read(n as usize);
    }
}

/// `re_keyval`, `^([^=]+)=(.*)$`, on a stripped line.
fn key_value(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once('=')?;
    if key.is_empty() || value.contains('\n') {
        return None;
    }
    Some((key, value))
}

/// The modules the PROJECT stream lists, with the extension each is written with.
fn code_modules(project: &[u8]) -> BTreeMap<String, &'static str> {
    let text = pystr::decode_utf8_ignore(project);
    let mut modules = BTreeMap::new();
    for line in text.split_inclusive('\n') {
        let line = pystr::strip(line);
        if line.is_empty() || line.starts_with('[') {
            continue;
        }
        let Some((key, value)) = key_value(line) else {
            continue;
        };
        match key {
            "Document" | "DocClass" => {
                modules.insert(value.split('/').next().unwrap_or("").to_owned(), "cls");
            }
            "Module" => {
                modules.insert(value.to_owned(), "bas");
            }
            "Class" => {
                modules.insert(value.to_owned(), "cls");
            }
            "BaseClass" => {
                modules.insert(value.to_owned(), "frm");
            }
            _ => {}
        }
    }
    modules
}

/// `--extract-macros`: each module's source, as `<module>.<ext>`.
fn extract_macros(doc: &Doc<'_>, out: &mut Out) -> R<()> {
    let Some(project) = doc.find_stream_by_name("PROJECT") else {
        return Ok(());
    };
    let code_modules = code_modules(&doc.get_stream(project)?);
    let Some(dir) = doc.find_stream_by_name("dir") else {
        return Ok(());
    };
    let decompressed = decompress_stream(&doc.get_stream(dir)?)?.unwrap_or_default();
    let mut d = Reader {
        data: decompressed,
        at: 0,
    };
    // PROJECTSYSKIND
    d.u16()?;
    d.u32()?;
    d.u32()?;
    // PROJECTCOMPATVERSION or PROJECTLCID
    let record = d.u16()?;
    if record == 0x004A || record == 0x0002 {
        d.u32()?;
        d.u32()?;
    }
    // PROJECTLCIDINVOKE
    d.u16()?;
    d.u32()?;
    d.u32()?;
    // PROJECTCODEPAGE
    d.u16()?;
    d.u32()?;
    d.u16()?;
    // PROJECTNAME
    d.u16()?;
    let size = d.u32()?;
    d.skip(size);
    // PROJECTDOCSTRING
    d.u16()?;
    let size = d.u32()?;
    d.skip(size);
    d.u16()?;
    let size = d.u32()?;
    d.skip(size);
    // PROJECTHELPFILEPATH
    d.u16()?;
    let size = d.u32()?;
    d.skip(size);
    d.u16()?;
    let size = d.u32()?;
    d.skip(size);
    // PROJECTHELPCONTEXT, PROJECTLIBFLAGS
    for _ in 0..2 {
        d.u16()?;
        d.u32()?;
        d.u32()?;
    }
    // PROJECTVERSION
    d.u16()?;
    d.u32()?;
    d.u32()?;
    d.u16()?;
    // PROJECTCONSTANTS
    d.u16()?;
    let size = d.u32()?;
    d.skip(size);
    d.u16()?;
    let size = d.u32()?;
    d.skip(size);
    // REFERENCE records, until PROJECTMODULES
    loop {
        let check = d.u16()?;
        match check {
            0x000F => break,
            0x0016 => {
                let size = d.u32()?;
                d.skip(size);
                d.u16()?;
                let size = d.u32()?;
                d.skip(size);
            }
            0x0033 => {
                let size = d.u32()?;
                d.skip(size);
            }
            0x002F => {
                d.u32()?;
                let size = d.u32()?;
                d.skip(size);
                d.u32()?;
                d.u16()?;
                let check2 = d.u16()?;
                if check2 == 0x0016 {
                    let size = d.u32()?;
                    d.skip(size);
                    d.u16()?;
                    let size = d.u32()?;
                    d.skip(size);
                    d.u16()?;
                }
                d.u32()?;
                let size = d.u32()?;
                d.skip(size);
                d.u32()?;
                d.u16()?;
                d.skip(16);
                d.u32()?;
            }
            0x000D => {
                d.u32()?;
                let size = d.u32()?;
                d.skip(size);
                d.u32()?;
                d.u16()?;
            }
            0x000E => {
                d.u32()?;
                let size = d.u32()?;
                d.skip(size);
                let size = d.u32()?;
                d.skip(size);
                d.u32()?;
                d.u16()?;
            }
            _ => return Err(Stop::Exit),
        }
    }
    // PROJECTMODULES
    d.u32()?;
    let count = d.u16()?;
    d.u16()?;
    d.u32()?;
    d.u16()?;
    // locals of _main, which keep their values from one module to the next
    let mut stream_name: Option<String> = None;
    let mut text_offset: Option<u32> = None;
    for _ in 0..count {
        d.u16()?;
        let size = d.u32()?;
        let module_name = pystr::decode_utf8_ignore(d.read(size as usize)).into_owned();
        let mut section = Some(d.u16()?);
        if section == Some(0x0047) {
            let size = d.u32()?;
            d.skip(size);
            section = Some(d.u16()?);
        }
        if section == Some(0x001A) {
            let size = d.u32()?;
            stream_name = Some(pystr::decode_utf8_ignore(d.read(size as usize)).into_owned());
            d.u16()?;
            let size = d.u32()?;
            d.skip(size);
            section = Some(d.u16()?);
        }
        if section == Some(0x001C) {
            let size = d.u32()?;
            d.skip(size);
            d.u16()?;
            let size = d.u32()?;
            d.skip(size);
            section = Some(d.u16()?);
        }
        if section == Some(0x0031) {
            d.u32()?;
            text_offset = Some(d.u32()?);
            section = Some(d.u16()?);
        }
        if section == Some(0x001E) {
            d.u32()?;
            d.u32()?;
            section = Some(d.u16()?);
        }
        if section == Some(0x002C) {
            d.u32()?;
            d.u16()?;
            section = Some(d.u16()?);
        }
        if matches!(section, Some(0x0021 | 0x0022)) {
            d.u32()?;
            section = Some(d.u16()?);
        }
        if section == Some(0x0025) {
            d.u32()?;
            section = Some(d.u16()?);
        }
        if section == Some(0x0028) {
            d.u32()?;
            section = Some(d.u16()?);
        }
        if section == Some(0x002B) {
            d.u32()?;
        }
        // the debug lines name both, unbound before a module sets them
        let Some(stream) = stream_name.clone() else {
            return raise("UnboundLocalError: MODULESTREAMNAME_StreamName");
        };
        let Some(offset) = text_offset else {
            return raise("UnboundLocalError: MODULEOFFSET_TextOffset");
        };
        let Some(code_stream) = doc.find_stream_by_name(&stream) else {
            continue;
        };
        let code = doc.get_stream(code_stream)?;
        let code = &code[(offset as usize).min(code.len())..];
        if code.is_empty() {
            continue;
        }
        let code = decompress_stream(code)?;
        let Some(ext) = code_modules.get(&module_name) else {
            return raise(format!("KeyError: {module_name:?}"));
        };
        let mut filename = format!("{module_name}.{ext}");
        let mut counter = 1;
        while exists(&out.files, &filename) {
            filename = format!("{module_name}_{counter}.{ext}");
            counter += 1;
        }
        let file = out.create(&filename)?;
        let Some(code) = code else {
            return raise("TypeError: a bytes-like object is required, not 'NoneType'");
        };
        out.write(&file, Rc::new(code));
        out.list(&filename);
    }
    Ok(())
}

/// `--extract-unknown-sectors`: what follows the sectors the FAT covers.
fn extract_unknown_sectors(doc: &Doc<'_>, out: &mut Out) -> R<()> {
    let mut i = 0;
    let name = loop {
        let name = format!("unknown_sectors_{i}.dat");
        if !exists(&out.files, &name) {
            break name;
        }
        i += 1;
    };
    let size = doc.sector_size.0.unwrap_or(u128::MAX);
    let offset = 512u128.saturating_add((doc.fat.len() as u128).saturating_mul(size));
    let start = offset.min(doc.data.len() as u128) as usize;
    let file = out.create(&name)?;
    out.write(&file, Rc::new(doc.data[start..].to_vec()));
    out.list(&name);
    Ok(())
}

/// Whether ace3 runs officeparser3 on the file at all: it starts with the OLE signature.
pub fn is_ole(data: &[u8]) -> bool {
    data.starts_with(OLE_SIGNATURE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompression_follows_python() {
        // a literal chunk, then a copy token that reaches back
        let mut data = vec![0x01, 0x05, 0xB0, 0x00];
        data.extend(b"abcdefg");
        assert_eq!(
            decompress_stream(&[0x01, 0x03, 0xB0, 0x00, b'a', b'b']).unwrap(),
            Some(b"ab".to_vec())
        );
        assert_eq!(decompress_stream(b"\x02").unwrap(), None);
        assert!(decompress_stream(b"").is_err());
        // a copy token first: log(0) raises
        assert!(decompress_stream(&[0x01, 0x03, 0xB0, 0x01, 0, 0]).is_err());
    }

    #[test]
    fn names_are_opened_as_the_kernel_opens_them() {
        let files = BTreeMap::from([("a".to_owned(), Rc::default())]);
        assert!(matches!(open_for_write(&files, "x"), Ok(Opened::Here(n)) if n == "x"));
        assert!(matches!(
            open_for_write(&files, "../x"),
            Ok(Opened::Elsewhere)
        ));
        assert!(matches!(open_for_write(&files, "./x"), Ok(Opened::Here(_))));
        assert!(open_for_write(&files, "a/x").is_err());
        assert!(open_for_write(&files, "b/x").is_err());
        assert!(open_for_write(&files, "").is_err());
        assert!(open_for_write(&files, "..").is_err());
        assert!(open_for_write(&files, "/etc/x").is_err());
        assert!(open_for_write(&files, &"n".repeat(256)).is_err());
    }

    #[test]
    fn a_sector_size_python_won_t_print_raises_before_the_manifest() {
        let mut header = vec![0u8; 512];
        header[..8].copy_from_slice(OLE_SIGNATURE);
        header[30..32].copy_from_slice(&(MAX_PRINTED_SHIFT - 1).to_le_bytes());
        header[32..34].copy_from_slice(&MAX_PRINTED_SHIFT.to_le_bytes());
        let run = run(&header);
        assert!(!run.manifest);
        assert!(matches!(&run.end, End::Raised(m) if m.contains("4300 digits")));
    }

    #[test]
    fn not_a_compound_file_raises_before_the_manifest() {
        let run = run(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1 short");
        assert!(!run.manifest);
        assert!(matches!(run.end, End::Raised(_)));
    }
}
