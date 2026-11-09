//! PngImagePlugin: PNG and APNG (the first frame, or the default image).

use crate::Raise;
use crate::image::{Canvas, Mode, Palette};
use crate::inflate::{Inflate, Status, decompress_limited};
use crate::io::{File, u16be, u32be};
use crate::open::{Load, Opened};
use crate::unpack::{self, Unpacker};

const MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
const SAFEBLOCK: usize = 1024 * 1024;
const MAX_TEXT_CHUNK: usize = SAFEBLOCK;
const MAX_TEXT_MEMORY: usize = 64 * MAX_TEXT_CHUNK;
const MAXBLOCK: usize = 65536;

pub(crate) fn accept(prefix: &[u8]) -> Result<bool, Raise> {
    Ok(prefix.starts_with(MAGIC))
}

pub(crate) fn crc32(data: &[u8], seed: u32) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *e = c;
        }
        t
    });
    let mut c = !seed;
    for &b in data {
        c = t[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

fn mode_of(depth: u8, ctype: u8) -> Option<(&'static str, &'static str)> {
    Some(match (depth, ctype) {
        (1, 0) => ("1", "1"),
        (2, 0) => ("L", "L;2"),
        (4, 0) => ("L", "L;4"),
        (8, 0) => ("L", "L"),
        (16, 0) => ("I;16", "I;16B"),
        (8, 2) => ("RGB", "RGB"),
        (16, 2) => ("RGB", "RGB;16B"),
        (1, 3) => ("P", "P;1"),
        (2, 3) => ("P", "P;2"),
        (4, 3) => ("P", "P;4"),
        (8, 3) => ("P", "P"),
        (8, 4) => ("LA", "LA"),
        (16, 4) => ("RGBA", "LA;16B"),
        (8, 6) => ("RGBA", "RGBA"),
        (16, 6) => ("RGBA", "RGBA;16B"),
        _ => return None,
    })
}

fn is_cid(cid: &[u8]) -> bool {
    cid.len() >= 4
        && cid[..4]
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || c == b'_')
}

/// What a chunk handler did, beyond returning its data.
enum Handled<'a> {
    Data(&'a [u8]),
    /// IDAT, IEND or fdAT raised EOFError.
    Eof,
    /// No `chunk_<cid>` method: AttributeError.
    Unknown,
}

/// PngStream's state.
struct Stream {
    mode: String,
    rawmode: &'static str,
    size: (i64, i64),
    interlace: bool,
    palette: Option<Vec<u8>>,
    n_frames: Option<u32>,
    default_image: bool,
    seq_num: Option<u32>,
    bbox: Option<(i64, i64, i64, i64)>,
    tile: Option<(i64, i64, i64, i64, usize)>,
    text_memory: usize,
    /// A chunk header pushed back by load_read.
    queue: Option<(Vec<u8>, usize, usize)>,
}

impl Stream {
    fn new() -> Self {
        Stream {
            mode: String::new(),
            rawmode: "",
            size: (0, 0),
            interlace: false,
            palette: None,
            n_frames: None,
            default_image: false,
            seq_num: None,
            bbox: None,
            tile: None,
            text_memory: 0,
            queue: None,
        }
    }

    /// ChunkStream.read: (cid, pos, length).
    fn read(&mut self, f: &mut File) -> Result<(Vec<u8>, usize, usize), Raise> {
        let (cid, pos, length) = if let Some(q) = self.queue.take() {
            f.seek(q.1);
            q
        } else {
            let s = f.read(8);
            let cid = s.get(4..).unwrap_or(&[]).to_vec();
            let pos = f.tell();
            let length = u32be(s, 0)? as usize;
            (cid, pos, length)
        };
        if !is_cid(&cid) {
            return Err(Raise::syntax(format!("broken PNG file (chunk {:?})", cid)));
        }
        Ok((cid, pos, length))
    }

    fn check_text_memory(&mut self, n: usize) -> Result<(), Raise> {
        self.text_memory += n;
        if self.text_memory > MAX_TEXT_MEMORY {
            return Err(Raise::value("Too much memory used in text chunks"));
        }
        Ok(())
    }

    fn call<'a>(
        &mut self,
        f: &mut File<'a>,
        cid: &[u8],
        pos: usize,
        length: usize,
    ) -> Result<Handled<'a>, Raise> {
        let name = &cid[..4];
        match name {
            b"IHDR" => {
                let s = f.safe_read(length)?;
                if length < 13 {
                    return Err(Raise::value("Truncated IHDR chunk"));
                }
                self.size = (u32be(s, 0)? as i64, u32be(s, 4)? as i64);
                if let Some((m, r)) = mode_of(s[8], s[9]) {
                    self.mode = m.to_string();
                    self.rawmode = r;
                }
                if s[12] != 0 {
                    self.interlace = true;
                }
                if s[11] != 0 {
                    return Err(Raise::syntax("unknown filter category"));
                }
                Ok(Handled::Data(s))
            }
            b"IDAT" => {
                if self.bbox.is_none() && self.n_frames.is_some() {
                    self.default_image = true;
                }
                let b = self.bbox.unwrap_or((0, 0, self.size.0, self.size.1));
                self.tile = Some((b.0, b.1, b.2, b.3, pos));
                let _ = length;
                Ok(Handled::Eof)
            }
            b"IEND" => Ok(Handled::Eof),
            b"PLTE" => {
                let s = f.safe_read(length)?;
                if self.mode == "P" {
                    self.palette = Some(s.to_vec());
                }
                Ok(Handled::Data(s))
            }
            b"tRNS" => {
                let s = f.safe_read(length)?;
                if matches!(self.mode.as_str(), "1" | "L" | "I;16" | "RGB") {
                    let need = if self.mode == "RGB" { 6 } else { 2 };
                    if length < need {
                        return Err(Raise::value("Truncated tRNS chunk"));
                    }
                }
                Ok(Handled::Data(s))
            }
            b"gAMA" | b"cHRM" | b"sRGB" | b"pHYs" | b"acTL" | b"fcTL" => {
                let s = f.safe_read(length)?;
                let need = match name {
                    b"gAMA" => 4,
                    b"cHRM" => 32,
                    b"sRGB" => 1,
                    b"pHYs" => 9,
                    b"acTL" => 8,
                    _ => 26,
                };
                if length < need {
                    return Err(Raise::value("Truncated chunk"));
                }
                if name == b"acTL" {
                    if self.n_frames.is_some() {
                        self.n_frames = None;
                    } else {
                        let n = u32be(s, 0)?;
                        if !(n == 0 || n > 0x8000_0000) {
                            self.n_frames = Some(n);
                        }
                    }
                } else if name == b"fcTL" {
                    let seq = u32be(s, 0)?;
                    let bad = match self.seq_num {
                        None => seq != 0,
                        Some(prev) => seq == 0 || prev != seq - 1,
                    };
                    if bad {
                        return Err(Raise::syntax("APNG contains frame sequence errors"));
                    }
                    self.seq_num = Some(seq);
                    let (w, h) = (u32be(s, 4)? as i64, u32be(s, 8)? as i64);
                    let (px, py) = (u32be(s, 12)? as i64, u32be(s, 16)? as i64);
                    if px + w > self.size.0 || py + h > self.size.1 {
                        return Err(Raise::syntax("APNG contains invalid frames"));
                    }
                    self.bbox = Some((px, py, px + w, py + h));
                    let _ = (u16be(s, 20)?, u16be(s, 22)?);
                }
                Ok(Handled::Data(s))
            }
            b"tEXt" => {
                let s = f.safe_read(length)?;
                let (k, v) = match s.iter().position(|&c| c == 0) {
                    Some(i) => (&s[..i], &s[i + 1..]),
                    None => (s, &[][..]),
                };
                if !k.is_empty() {
                    self.check_text_memory(v.len())?;
                }
                Ok(Handled::Data(s))
            }
            b"zTXt" => {
                let s = f.safe_read(length)?;
                let (k, v) = match s.iter().position(|&c| c == 0) {
                    Some(i) => (&s[..i], &s[i + 1..]),
                    None => (s, &[][..]),
                };
                let comp = v.first().copied().unwrap_or(0);
                if comp != 0 {
                    return Err(Raise::syntax("Unknown compression method in zTXt chunk"));
                }
                let text = match decompress_limited(v.get(1..).unwrap_or(&[]), MAX_TEXT_CHUNK) {
                    Ok((_, true)) => {
                        return Err(Raise::value(
                            "Decompressed data too large for PngImagePlugin.MAX_TEXT_CHUNK",
                        ));
                    }
                    Ok((t, false)) => t.len(),
                    Err(()) => 0,
                };
                if !k.is_empty() {
                    self.check_text_memory(text)?;
                }
                Ok(Handled::Data(s))
            }
            b"iTXt" => {
                let s = f.safe_read(length)?;
                self.itxt(s)?;
                Ok(Handled::Data(s))
            }
            b"iCCP" => {
                let s = f.safe_read(length)?;
                let i = s.iter().position(|&c| c == 0).map_or(-1i64, |i| i as i64);
                let at = (i + 1) as usize;
                let comp = *s.get(at).ok_or_else(Raise::index_error)?;
                if comp != 0 {
                    return Err(Raise::syntax("Unknown compression method in iCCP chunk"));
                }
                let rest = s.get(at + 1..).unwrap_or(&[]);
                if let Ok((_, true)) = decompress_limited(rest, MAX_TEXT_CHUNK) {
                    return Err(Raise::value(
                        "Decompressed data too large for PngImagePlugin.MAX_TEXT_CHUNK",
                    ));
                }
                Ok(Handled::Data(s))
            }
            b"eXIf" => Ok(Handled::Data(f.safe_read(length)?)),
            b"fdAT" => {
                if length < 4 {
                    return Err(Raise::value("APNG contains truncated fDAT chunk"));
                }
                let s = f.safe_read(4)?;
                let seq = u32be(s, 0)?;
                let ok = match self.seq_num {
                    Some(prev) => seq != 0 && prev == seq - 1,
                    None => false,
                };
                if !ok {
                    return Err(Raise::syntax("APNG contains frame sequence errors"));
                }
                self.seq_num = Some(seq);
                self.call(f, b"IDAT", pos + 4, length - 4)
            }
            _ => Ok(Handled::Unknown),
        }
    }

    fn itxt(&mut self, s: &[u8]) -> Result<(), Raise> {
        let Some(i) = s.iter().position(|&c| c == 0) else {
            return Ok(());
        };
        let r = &s[i + 1..];
        if r.len() < 2 {
            return Ok(());
        }
        let (cf, cm, r) = (r[0], r[1], &r[2..]);
        let Some(a) = r.iter().position(|&c| c == 0) else {
            return Ok(());
        };
        let Some(b) = r[a + 1..].iter().position(|&c| c == 0) else {
            return Ok(());
        };
        let (lang, tk, v) = (&r[..a], &r[a + 1..a + 1 + b], &r[a + 2 + b..]);
        let owned;
        let v = if cf != 0 {
            if cm != 0 {
                return Ok(());
            }
            match decompress_limited(v, MAX_TEXT_CHUNK) {
                Ok((_, true)) => {
                    return Err(Raise::value(
                        "Decompressed data too large for PngImagePlugin.MAX_TEXT_CHUNK",
                    ));
                }
                Ok((t, false)) => {
                    owned = t;
                    &owned[..]
                }
                Err(()) => return Ok(()),
            }
        } else {
            v
        };
        let (Ok(_), Ok(_), Ok(vs)) = (
            std::str::from_utf8(lang),
            std::str::from_utf8(tk),
            std::str::from_utf8(v),
        ) else {
            return Ok(());
        };
        let n = vs.chars().count();
        self.check_text_memory(n)
    }

    /// ChunkStream.crc.
    fn crc(&self, f: &mut File, cid: &[u8], data: &[u8]) -> Result<(), Raise> {
        let crc1 = crc32(data, crc32(cid, 0));
        let crc2 = u32be(f.read(4), 0)
            .map_err(|_| Raise::syntax("broken PNG file (incomplete checksum)"))?;
        if crc1 != crc2 {
            return Err(Raise::syntax("broken PNG file (bad header checksum)"));
        }
        Ok(())
    }
}

pub(crate) fn open(data: &[u8]) -> Result<Opened<'_>, Raise> {
    open_at(data, 0)
}

/// `PngImageFile(fp)` with the file at `start` (as IcoFile opens an embedded PNG).
pub(crate) fn open_at(data: &[u8], start: usize) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(data);
    f.seek(start);
    if !f.read(8).starts_with(MAGIC) {
        return Err(Raise::syntax("not a PNG file"));
    }
    let mut png = Stream::new();
    let (last_cid, last_len) = loop {
        let (cid, pos, length) = png.read(&mut f)?;
        let s = match png.call(&mut f, &cid, pos, length)? {
            Handled::Eof => break (cid, length),
            Handled::Data(s) => s,
            Handled::Unknown => f.safe_read(length)?,
        };
        png.crc(&mut f, &cid, s)?;
    };
    let prepare_idat = if &last_cid[..4] == b"fdAT" {
        last_len - 4
    } else {
        last_len
    };
    let mode = png.mode.clone();
    let size = png.size;
    let after = f.tell();
    let animated =
        png.n_frames.unwrap_or(1) as u64 + (png.n_frames.is_some() && png.default_image) as u64 > 1;
    Ok(Opened::new(
        "PNG",
        mode,
        size,
        Box::new(PngLoad {
            data,
            png,
            prepare_idat,
            after,
            animated,
        }),
    ))
}

struct PngLoad<'a> {
    data: &'a [u8],
    png: Stream,
    prepare_idat: usize,
    /// Where the file was left by `_open`.
    after: usize,
    animated: bool,
}

impl Load for PngLoad<'_> {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        let PngLoad {
            data,
            mut png,
            prepare_idat,
            after,
            animated,
        } = *self;
        let Some((x0, y0, x1, y1, offset)) = png.tile else {
            return Err(Raise::os("cannot load this image"));
        };
        let mode = Mode::from_name(&png.mode).ok_or_else(Raise::key)?;
        let (w, h) = (png.size.0 as usize, png.size.1 as usize);
        let mut canvas = Canvas::new(mode, w, h)?;
        if mode == Mode::P {
            if let Some(p) = &png.palette {
                canvas.palette = Some(Palette::from_raw(p, 3, [0, 1, 2])?);
            }
        }
        let u = unpack::find(mode, png.rawmode)
            .ok_or_else(|| Raise::value("unknown raw mode for given image mode"))?;
        if x0 < 0 || y0 < 0 || x1 <= x0 || y1 <= y0 || x1 > w as i64 || y1 > h as i64 {
            return Err(Raise::value("tile cannot extend outside image"));
        }
        let mut f = File::new(data);
        let _ = after;
        f.seek(offset);
        let mut dec = ZipDecoder::new(
            u,
            png.interlace,
            (x0 as usize, y0 as usize, x1 as usize, y1 as usize),
        )?;
        let mut idat = prepare_idat;
        let err_code: i32;
        loop {
            // load_read(MAXBLOCK)
            let s: &[u8] = loop {
                if idat != 0 {
                    let n = MAXBLOCK.min(idat);
                    idat -= n;
                    break f.read(n);
                }
                f.read(4);
                let (cid, pos, length) = match png.read(&mut f) {
                    Ok(c) => c,
                    Err(e) if e.kind == crate::Kind::StructError => return Err(Raise::truncated()),
                    Err(e) => return Err(e),
                };
                match &cid[..4] {
                    b"IDAT" | b"DDAT" => idat = length,
                    b"fdAT" => {
                        png.call(&mut f, &cid, pos, length)?;
                        idat = length - 4;
                    }
                    _ => {
                        png.queue = Some((cid, pos, length));
                        break &[];
                    }
                }
            };
            if s.is_empty() {
                return Err(Raise::truncated());
            }
            let (done, code) = dec.decode(s, &mut canvas);
            if done {
                err_code = code;
                break;
            }
        }
        // load_end
        if idat != 0 {
            f.read(idat);
        }
        loop {
            f.read(4);
            let (cid, pos, length) = match png.read(&mut f) {
                Ok(c) => c,
                Err(e) if matches!(e.kind, crate::Kind::StructError | crate::Kind::SyntaxError) => {
                    break;
                }
                Err(e) => return Err(e),
            };
            if &cid[..4] == b"IEND" {
                break;
            }
            if &cid[..4] == b"fcTL" && animated {
                break;
            }
            match png.call(&mut f, &cid, pos, length)? {
                Handled::Data(_) => {}
                Handled::Eof => {
                    let l = if &cid[..4] == b"fdAT" {
                        length - 4
                    } else {
                        length
                    };
                    f.safe_read(l)?;
                }
                Handled::Unknown => {
                    f.safe_read(length)?;
                }
            }
        }
        if err_code < 0 {
            return Err(Raise::decoder(err_code));
        }
        Ok(canvas)
    }
}

const OFFSET: [usize; 7] = [7, 3, 3, 1, 1, 0, 0];
const STARTING_COL: [usize; 7] = [0, 4, 0, 2, 0, 1, 0];
const STARTING_ROW: [usize; 7] = [0, 0, 4, 0, 2, 0, 1];
const COL_INCREMENT: [usize; 7] = [8, 8, 4, 4, 2, 2, 1];
const ROW_INCREMENT: [usize; 7] = [8, 8, 8, 4, 4, 2, 2];

/// Pillow's ZipDecode.c in PNG mode.
pub(crate) struct ZipDecoder {
    z: Inflate,
    u: Unpacker,
    bits: usize,
    bytes: usize,
    xoff: usize,
    yoff: usize,
    xsize: usize,
    ysize: usize,
    y: usize,
    interlaced: bool,
    pass: usize,
    buffer: Vec<u8>,
    previous: Vec<u8>,
    last_output: usize,
    /// 1 for PNG (a filter byte a row), 0 for TIFF.
    prefix: usize,
    tiff_predictor: bool,
}

impl ZipDecoder {
    pub(crate) fn new(
        u: Unpacker,
        interlaced: bool,
        extents: (usize, usize, usize, usize),
    ) -> Result<Self, Raise> {
        let xsize = extents.2 - extents.0;
        let ysize = extents.3 - extents.1;
        let bits = u.bits;
        let bytes = (bits * xsize).div_ceil(8);
        if bytes > i32::MAX as usize - 1 {
            return Err(Raise::decoder(-9));
        }
        Ok(ZipDecoder {
            z: Inflate::new(),
            u,
            bits,
            bytes,
            xoff: extents.0,
            yoff: extents.1,
            xsize,
            ysize,
            y: if interlaced { STARTING_ROW[0] } else { 0 },
            interlaced,
            pass: 0,
            buffer: vec![0; bytes + 1],
            previous: vec![0; bytes + 1],
            last_output: 0,
            prefix: 1,
            tiff_predictor: false,
        })
    }

    fn row_len(&self, pass: usize) -> usize {
        let n = (self.xsize + OFFSET[pass]) / COL_INCREMENT[pass];
        (n * self.bits).div_ceil(8)
    }

    /// One `decoder.decode(buffer)` call: (finished, errcode). Unfinished means it took
    /// all of the buffer.
    pub(crate) fn decode(&mut self, buf: &[u8], im: &mut Canvas) -> (bool, i32) {
        let mut row_len = if self.interlaced {
            self.row_len(self.pass)
        } else {
            self.bytes
        };
        let mut pos = 0;
        while pos < buf.len() {
            let want = row_len + self.prefix;
            let (used, n, st) = {
                let out = &mut self.buffer[self.last_output..want];
                self.z.inflate(&buf[pos..], out)
            };
            pos += used;
            if let Status::DataError(_) = st {
                return (true, -2);
            }
            let filled = self.last_output + n;
            if filled < want {
                self.last_output = filled;
                if used == 0 && n == 0 {
                    // zlib makes no progress after the end of the stream (or while it
                    // wants a dictionary): Pillow still reports the whole buffer used.
                    break;
                }
                continue;
            }
            let stream_end = st == Status::StreamEnd;
            // the predictor
            let bpp = self.bits.div_ceil(8);
            if self.prefix == 1 {
                let b = &mut self.buffer;
                let p = &self.previous;
                match b[0] {
                    0 => {}
                    1 => {
                        for i in bpp + 1..=row_len {
                            b[i] = b[i].wrapping_add(b[i - bpp]);
                        }
                    }
                    2 => {
                        for i in 1..=row_len {
                            b[i] = b[i].wrapping_add(p[i]);
                        }
                    }
                    3 => {
                        let mut i = 1;
                        while i <= bpp && i <= row_len {
                            b[i] = b[i].wrapping_add(p[i] / 2);
                            i += 1;
                        }
                        while i <= row_len {
                            b[i] = b[i].wrapping_add(((b[i - bpp] as u32 + p[i] as u32) / 2) as u8);
                            i += 1;
                        }
                    }
                    4 => {
                        let mut i = 1;
                        while i <= bpp && i <= row_len {
                            b[i] = b[i].wrapping_add(p[i]);
                            i += 1;
                        }
                        while i <= row_len {
                            let a = b[i - bpp] as i32;
                            let bb = p[i] as i32;
                            let c = p[i - bpp] as i32;
                            let pa = (bb - c).abs();
                            let pb = (a - c).abs();
                            let pc = (a + bb - 2 * c).abs();
                            let v = if pa <= pb && pa <= pc {
                                a
                            } else if pb <= pc {
                                bb
                            } else {
                                c
                            };
                            b[i] = b[i].wrapping_add(v as u8);
                            i += 1;
                        }
                    }
                    _ => return (true, -3),
                }
            } else if self.tiff_predictor {
                let b = &mut self.buffer;
                for i in bpp..row_len {
                    b[i] = b[i].wrapping_add(b[i - bpp]);
                }
            }
            if self.interlaced {
                let mut col = STARTING_COL[self.pass];
                let data = &self.buffer[self.prefix..];
                if self.bits >= 8 {
                    let step = bpp;
                    let mut i = 0;
                    while i < row_len {
                        im.unpack_row(&self.u, col, self.y, &data[i..], 1);
                        col += COL_INCREMENT[self.pass];
                        i += step;
                    }
                } else {
                    let row_bits =
                        ((self.xsize + OFFSET[self.pass]) / COL_INCREMENT[self.pass]) * self.bits;
                    let mut i = 0;
                    while i < row_bits {
                        let byte = data[i / 8] << (i % 8);
                        im.unpack_row(&self.u, col, self.y, &[byte], 1);
                        col += COL_INCREMENT[self.pass];
                        i += self.bits;
                    }
                }
                self.y += ROW_INCREMENT[self.pass];
                while self.y >= self.ysize || row_len == 0 {
                    self.pass += 1;
                    if self.pass == 7 {
                        self.y = self.ysize;
                        break;
                    }
                    self.y = STARTING_ROW[self.pass];
                    row_len = self.row_len(self.pass);
                    self.buffer.fill(0);
                }
            } else {
                im.unpack_row(
                    &self.u,
                    self.xoff,
                    self.y + self.yoff,
                    &self.buffer[self.prefix..],
                    self.xsize,
                );
                self.y += 1;
            }
            self.last_output = 0;
            if self.y >= self.ysize || stream_end {
                return (true, 0);
            }
            std::mem::swap(&mut self.buffer, &mut self.previous);
        }
        (false, 0)
    }
}
