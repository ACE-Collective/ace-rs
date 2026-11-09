//! The small plugins: QOI, SGI, MSP, SUN, XBM, XPM, IMT, IPTC, McIdas, PIXAR, XV thumbnails,
//! GIMP brushes, FTEX, FLI, FITS, BLP, PCD, MPEG and SPIDER.

use super::raw::{self, RawTile};
use crate::Raise;
use crate::image::{Canvas, Mode, Palette};
use crate::io::{File, byte, u16be, u16le, u32be, u32le};
use crate::open::{Fails, Load, NoDecoder, Opened, bomb_check};
use crate::pyparse::py_int;
use crate::unpack;

fn find(mode: Mode, raw: &str) -> Result<unpack::Unpacker, Raise> {
    unpack::find(mode, raw).ok_or_else(|| Raise::value("unknown raw mode for given image mode"))
}

/// A load made of raw tiles (ImageFile.load with the "raw" decoder).
struct RawLoad<'a> {
    data: &'a [u8],
    mode: Mode,
    size: (usize, usize),
    tiles: Vec<(usize, String, usize, bool)>,
    palette: Option<Palette>,
}

impl Load for RawLoad<'_> {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        let mut c = Canvas::new(self.mode, self.size.0, self.size.1)?;
        c.palette = self.palette;
        let mut tiles = Vec::new();
        for (off, rm, stride, bottom_up) in &self.tiles {
            let u = find(self.mode, rm)?;
            if u.partial && c.native.is_none() {
                c.keep_native()?;
            }
            tiles.push(RawTile {
                x0: 0,
                y0: 0,
                x1: self.size.0,
                y1: self.size.1,
                offset: *off,
                u,
                stride: *stride,
                bottom_up: *bottom_up,
            });
        }
        if tiles.is_empty() {
            return Err(Raise::os("cannot load this image"));
        }
        raw::load_tiles(&mut c, self.data, &mut tiles)?;
        Ok(c)
    }
}

fn usize_size(s: (i64, i64)) -> (usize, usize) {
    (s.0.max(0) as usize, s.1.max(0) as usize)
}

// ---------------------------------------------------------------- QOI

pub(crate) fn qoi_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"qoif"))
}

pub(crate) fn qoi_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(d);
    if !qoi_accept(f.read(4))? {
        return Err(Raise::syntax("not a QOI file"));
    }
    let w = u32be(f.read(4), 0)? as i64;
    let h = u32be(f.read(4), 0)? as i64;
    let channels = byte(f.read(1), 0)?;
    let mode = if channels == 3 { "RGB" } else { "RGBA" };
    f.skip(1);
    let off = f.tell();
    Ok(Opened::new(
        "QOI",
        mode,
        (w, h),
        Box::new(QoiLoad {
            data: d,
            off,
            mode,
            size: (w, h),
        }),
    ))
}

struct QoiLoad<'a> {
    data: &'a [u8],
    off: usize,
    mode: &'static str,
    size: (i64, i64),
}

impl Load for QoiLoad<'_> {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        let mode = Mode::from_name(self.mode).ok_or_else(Raise::key)?;
        let (w, h) = usize_size(self.size);
        let mut c = Canvas::new(mode, w, h)?;
        let bands = if mode == Mode::Rgb { 3 } else { 4 };
        let dest = w * h * bands;
        let mut seen: [Option<[u8; 4]>; 64] = [None; 64];
        let mut prev = [0u8, 0, 0, 255];
        let mut out: Vec<u8> = Vec::new();
        let mut f = File::new(self.data);
        f.seek(self.off);
        while out.len() < dest {
            let b = f.read(1);
            let Some(&byte) = b.first() else { break };
            let value: [u8; 4];
            if byte == 0xFE {
                let r = f.read(3);
                if r.len() < 3 {
                    break;
                }
                value = [r[0], r[1], r[2], prev[3]];
            } else if byte == 0xFF {
                let r = f.read(4);
                if r.len() < 4 {
                    break;
                }
                value = [r[0], r[1], r[2], r[3]];
            } else {
                match byte >> 6 {
                    0 => value = seen[(byte & 63) as usize].unwrap_or([0, 0, 0, 0]),
                    1 => {
                        value = [
                            (prev[0] as i32 + ((byte as i32 & 0x30) >> 4) - 2).rem_euclid(256)
                                as u8,
                            (prev[1] as i32 + ((byte as i32 & 0x0c) >> 2) - 2).rem_euclid(256)
                                as u8,
                            (prev[2] as i32 + (byte as i32 & 0x03) - 2).rem_euclid(256) as u8,
                            prev[3],
                        ]
                    }
                    2 => {
                        let s = f.read(1);
                        let Some(&s) = s.first() else { break };
                        let dg = (byte as i32 & 63) - 32;
                        let dr = ((s as i32 & 0xf0) >> 4) - 8;
                        let db = (s as i32 & 0x0f) - 8;
                        value = [
                            (prev[0] as i32 + dg + dr).rem_euclid(256) as u8,
                            (prev[1] as i32 + dg).rem_euclid(256) as u8,
                            (prev[2] as i32 + dg + db).rem_euclid(256) as u8,
                            prev[3],
                        ];
                    }
                    _ => {
                        let run = (byte & 63) as usize + 1;
                        for _ in 0..run {
                            out.extend_from_slice(&prev[..bands]);
                        }
                        continue;
                    }
                }
            }
            prev = value;
            let hsh = (value[0] as usize * 3
                + value[1] as usize * 5
                + value[2] as usize * 7
                + value[3] as usize * 11)
                % 64;
            seen[hsh] = Some(value);
            out.extend_from_slice(&value[..bands]);
        }
        raw::set_as_raw(&mut c, &out, find(mode, self.mode)?, 0, false)?;
        Ok(c)
    }
}

// ---------------------------------------------------------------- SGI

pub(crate) fn sgi_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.len() >= 2 && u16be(p, 0)? == 474)
}

pub(crate) fn sgi_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let s = &d[..d.len().min(512)];
    if !sgi_accept(s)? {
        return Err(Raise::value("Not an SGI image file"));
    }
    let comp = byte(s, 2)?;
    let bpc = byte(s, 3)?;
    let dim = u16be(s, 4)?;
    let (xs, ys, zs) = (u16be(s, 6)? as i64, u16be(s, 8)? as i64, u16be(s, 10)?);
    let rawmode = match (bpc, dim, zs) {
        (1, 1, 1) | (1, 2, 1) => "L",
        (2, 1, 1) | (2, 2, 1) => "L;16B",
        (1, 3, 3) => "RGB",
        (2, 3, 3) => "RGB;16B",
        (1, 3, 4) => "RGBA",
        (2, 3, 4) => "RGBA;16B",
        _ => return Err(Raise::value("Unsupported SGI image mode")),
    };
    let mode = rawmode.split(';').next().unwrap_or("L");
    let load: Box<dyn Load> = match comp {
        0 | 1 => Box::new(SgiLoad {
            data: d,
            mode,
            rawmode,
            size: (xs, ys),
            rle: comp == 1,
            bpc: bpc as usize,
        }),
        _ => Box::new(Fails(Raise::os("cannot load this image"))),
    };
    Ok(Opened::new("SGI", mode, (xs, ys), load))
}

struct SgiLoad<'a> {
    data: &'a [u8],
    mode: &'static str,
    rawmode: &'static str,
    size: (i64, i64),
    rle: bool,
    bpc: usize,
}

impl Load for SgiLoad<'_> {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        let mode = Mode::from_name(self.mode).ok_or_else(Raise::key)?;
        let (w, h) = usize_size(self.size);
        let mut c = Canvas::new(mode, w, h)?;
        let bands = self.mode.len();
        if self.rle {
            sgi_rle(
                &mut c,
                self.data,
                find(mode, self.rawmode)?,
                bands,
                self.bpc,
            )?;
            return Ok(c);
        }
        c.keep_native()?;
        let page = w * h * self.bpc;
        if self.bpc == 2 {
            // SGI16Decoder: each band through an "L" image from "L;16B" data
            for (band, _) in self.mode.chars().enumerate() {
                let start = 512 + band * 2 * page / 2;
                let chunk = self
                    .data
                    .get(start..(start + 2 * w * h).min(self.data.len()))
                    .unwrap_or(&[]);
                let mut ch = Canvas::new(Mode::L, w, h)?;
                raw::set_as_raw(&mut ch, chunk, find(Mode::L, "L;16B")?, 0, true)?;
                let n = c.native.as_mut().expect("native");
                let ps = mode.pixel_size();
                let chan = if mode == Mode::L { 0 } else { band };
                for (i, v) in ch.px.iter().enumerate() {
                    n[i * ps + chan] = *v;
                }
            }
            return Ok(c);
        }
        let mut tiles = Vec::new();
        for (i, layer) in self.mode.chars().enumerate() {
            tiles.push(RawTile {
                x0: 0,
                y0: 0,
                x1: w,
                y1: h,
                offset: 512 + i * page,
                u: find(mode, &layer.to_string())?,
                stride: 0,
                bottom_up: true,
            });
        }
        raw::load_tiles(&mut c, self.data, &mut tiles)?;
        Ok(c)
    }
}

/// SgiRleDecode.c.
fn sgi_rle(
    c: &mut Canvas,
    data: &[u8],
    u: unpack::Unpacker,
    bands: usize,
    bpc: usize,
) -> Result<(), Raise> {
    let (w, h) = (c.w, c.h);
    if data.len() < 512 {
        return Err(Raise::decoder(-3));
    }
    let buf = &data[512..];
    let bufsize = buf.len();
    let tablen = bands * h;
    if (bufsize as u64) < 8 * tablen as u64 {
        return Err(Raise::decoder(-1));
    }
    let start = |i: usize| u32be(buf, i * 4).unwrap_or(0) as usize;
    let length = |i: usize| u32be(buf, tablen * 4 + i * 4).unwrap_or(0) as i64;
    let mut row = vec![0u8; w * bands * 2];
    let end = bufsize - 1;
    for rowno in 0..h {
        let y = h - 1 - rowno;
        for ch in 0..bands {
            let off = start(rowno + ch * h);
            let n = length(rowno + ch * h);
            if off < 512 {
                return Err(Raise::decoder(-1));
            }
            let mut src = off - 512;
            let mut dest = if bpc == 1 { ch } else { ch * 2 };
            let mut x = 0usize;
            let mut n = n;
            let mut status = 0;
            while n > 0 {
                if bpc == 1 {
                    if src > end {
                        status = -1;
                        break;
                    }
                    let pixel = buf[src];
                    src += 1;
                    if n == 1 && pixel != 0 {
                        status = 1;
                        break;
                    }
                    let count = (pixel & 0x7f) as usize;
                    if count == 0 {
                        break;
                    }
                    if x + count > w {
                        status = -1;
                        break;
                    }
                    x += count;
                    if pixel & 0x80 != 0 {
                        if src + count > end + 1 && src + count > end {
                            status = -1;
                            break;
                        }
                        for _ in 0..count {
                            row[dest] = buf[src];
                            src += 1;
                            dest += bands;
                        }
                    } else {
                        if src > end {
                            status = -1;
                            break;
                        }
                        let p = buf[src];
                        src += 1;
                        for _ in 0..count {
                            row[dest] = p;
                            dest += bands;
                        }
                    }
                } else {
                    if src + 1 > end {
                        status = -1;
                        break;
                    }
                    let pixel = buf[src + 1];
                    src += 2;
                    if n == 1 && pixel != 0 {
                        status = 1;
                        break;
                    }
                    let count = (pixel & 0x7f) as usize;
                    if count == 0 {
                        break;
                    }
                    if x + count > w {
                        status = -1;
                        break;
                    }
                    x += count;
                    if pixel & 0x80 != 0 {
                        if src + 2 * count > end {
                            status = -1;
                            break;
                        }
                        for _ in 0..count {
                            row[dest] = buf[src];
                            row[dest + 1] = buf[src + 1];
                            src += 2;
                            dest += bands * 2;
                        }
                    } else {
                        if src + 2 > end {
                            status = -1;
                            break;
                        }
                        for _ in 0..count {
                            row[dest] = buf[src];
                            row[dest + 1] = buf[src + 1];
                            dest += bands * 2;
                        }
                        src += 2;
                    }
                }
                n -= 1;
            }
            if status == -1 {
                return Err(Raise::decoder(-1));
            }
            if status == 1 {
                return Ok(());
            }
        }
        c.unpack_row(&u, 0, y, &row, w);
    }
    Ok(())
}

// ---------------------------------------------------------------- MSP

pub(crate) fn msp_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"DanM") || p.starts_with(b"LinS"))
}

pub(crate) fn msp_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let s = &d[..d.len().min(32)];
    if !msp_accept(s)? {
        return Err(Raise::syntax("not an MSP file"));
    }
    let mut ck = 0u16;
    for i in (0..32).step_by(2) {
        ck ^= u16le(s, i)?;
    }
    if ck != 0 {
        return Err(Raise::syntax("bad MSP checksum"));
    }
    let size = (u16le(s, 4)? as i64, u16le(s, 6)? as i64);
    let load: Box<dyn Load> = if s.starts_with(b"DanM") {
        Box::new(RawLoad {
            data: d,
            mode: Mode::One,
            size: usize_size(size),
            tiles: vec![(32, "1".into(), 0, false)],
            palette: None,
        })
    } else {
        Box::new(MspLoad { data: d, size })
    };
    Ok(Opened::new("MSP", "1", size, load))
}

struct MspLoad<'a> {
    data: &'a [u8],
    size: (i64, i64),
}

impl Load for MspLoad<'_> {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        let (w, h) = usize_size(self.size);
        let mut c = Canvas::new(Mode::One, w, h)?;
        let mut f = File::new(self.data);
        f.seek(32);
        let map = f.read(h * 2);
        if map.len() < h * 2 {
            return Err(Raise::os("Truncated MSP file in row map"));
        }
        let blank = vec![0xFFu8; w.div_ceil(8)];
        let mut out = Vec::new();
        for y in 0..h {
            let len = u16le(map, y * 2)? as usize;
            if len == 0 {
                out.extend_from_slice(&blank);
                continue;
            }
            let row = f.read(len);
            if row.len() != len {
                return Err(Raise::os("Truncated MSP file"));
            }
            let mut idx = 0;
            let mut rd: Vec<u8> = Vec::new();
            while idx < len {
                let rt = row[idx];
                idx += 1;
                if rt == 0 {
                    if idx + 2 > len {
                        return Err(Raise::os("Corrupted MSP file"));
                    }
                    let (cnt, val) = (row[idx] as usize, row[idx + 1]);
                    let cnt = cnt.min(w.saturating_sub(rd.len()));
                    rd.extend(std::iter::repeat_n(val, cnt));
                    idx += 2;
                } else {
                    let cnt = (rt as usize).min(w.saturating_sub(rd.len()));
                    rd.extend_from_slice(&row[idx.min(len)..(idx + cnt).min(len)]);
                    idx += cnt;
                }
            }
            out.extend_from_slice(&rd);
        }
        raw::set_as_raw(&mut c, &out, find(Mode::One, "1")?, 0, false)?;
        Ok(c)
    }
}

// ---------------------------------------------------------------- SUN

pub(crate) fn sun_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.len() >= 4 && u32be(p, 0)? == 0x59A66A95)
}

pub(crate) fn sun_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(d);
    let s = f.read(32);
    if !sun_accept(s)? {
        return Err(Raise::syntax("not an SUN raster file"));
    }
    let size = (u32be(s, 4)? as i64, u32be(s, 8)? as i64);
    let depth = u32be(s, 12)?;
    let ftype = u32be(s, 20)?;
    let ptype = u32be(s, 24)?;
    let plen = u32be(s, 28)? as usize;
    let (mut mode, mut rawmode) = match depth {
        1 => ("1", "1;I".to_string()),
        4 => ("L", "L;4".to_string()),
        8 => ("L", "L".to_string()),
        24 => ("RGB", if ftype == 3 { "RGB" } else { "BGR" }.to_string()),
        32 => ("RGB", if ftype == 3 { "RGBX" } else { "BGRX" }.to_string()),
        _ => return Err(Raise::syntax("Unsupported Mode/Bit Depth")),
    };
    let mut offset = 32;
    let mut palette = None;
    if plen != 0 {
        if plen > 1024 {
            return Err(Raise::syntax("Unsupported Color Palette Length"));
        }
        if ptype != 1 {
            return Err(Raise::syntax("Unsupported Palette Type"));
        }
        offset += plen;
        let p = f.read(plen).to_vec();
        let n = p.len() / 3;
        let mut pal = Palette::default();
        for i in 0..n.min(256) {
            pal.rgba[i] = [p[i], p[i + n], p[i + 2 * n], 255];
        }
        palette = Some(pal);
        if mode == "L" {
            mode = "P";
            rawmode = rawmode.replace('L', "P");
        }
    }
    let stride = ((size.0.max(0) as u64 * depth as u64).div_ceil(16) * 2) as usize;
    let m = Mode::from_name(mode).ok_or_else(Raise::key)?;
    let load: Box<dyn Load> = match ftype {
        0 | 1 | 3 | 4 | 5 => Box::new(RawLoad {
            data: d,
            mode: m,
            size: usize_size(size),
            tiles: vec![(offset, rawmode, stride, false)],
            palette,
        }),
        2 => Box::new(NoDecoder("SUN RLE")),
        _ => return Err(Raise::syntax("Unsupported Sun Raster file type")),
    };
    Ok(Opened::new("SUN", mode, size, load))
}

// ---------------------------------------------------------------- XBM

pub(crate) fn xbm_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"#define") || p.starts_with(b"\n#define") || p.starts_with(b"/*"))
}

fn readline_limit<'a>(f: &mut File<'a>, limit: usize) -> &'a [u8] {
    let start = f.tell().min(f.len());
    let rest = &f.data()[start..];
    let n = match rest.iter().take(limit).position(|&b| b == b'\n') {
        Some(i) => i + 1,
        None => rest.len().min(limit),
    };
    f.read(n)
}

fn rstrip(b: &[u8]) -> &[u8] {
    let n = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace() && *c != 0x0b)
        .map_or(0, |i| i + 1);
    &b[..n]
}

pub(crate) fn xbm_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(d);
    let (mut width, mut height, mut offset) = (None, None, None);
    let mut starting = true;
    let mut in_comment = false;
    loop {
        let line = readline_limit(&mut f, 75);
        if line.is_empty() {
            break;
        }
        let line = rstrip(line);
        if in_comment {
            if line.ends_with(b"*/") {
                in_comment = false;
            }
            continue;
        }
        if line.starts_with(b"/*") {
            in_comment = !line.ends_with(b"*/");
            continue;
        }
        if starting && line.is_empty() {
            starting = false;
            continue;
        }
        if !line.starts_with(b"#define ") {
            if line.ends_with(b"_bits[] = {") {
                offset = Some(f.tell());
            }
            break;
        }
        let last = line
            .split(|c| c.is_ascii_whitespace())
            .rfind(|t| !t.is_empty())
            .unwrap_or(&[]);
        let value = py_int(last).ok_or_else(|| Raise::value("invalid literal for int()"))?;
        let has = |n: &[u8]| line.windows(n.len()).any(|w| w == n);
        if has(b"width ") {
            width = Some(value);
        } else if has(b"height ") {
            height = Some(value);
        }
    }
    let (Some(w), Some(h), Some(off)) = (width, height, offset) else {
        return Err(Raise::syntax("not a XBM file"));
    };
    let size = (w as i64, h as i64);
    Ok(Opened::new(
        "XBM",
        "1",
        size,
        Box::new(XbmLoad { data: d, off, size }),
    ))
}

struct XbmLoad<'a> {
    data: &'a [u8],
    off: usize,
    size: (i64, i64),
}

impl Load for XbmLoad<'_> {
    /// XbmDecode.c: after each "x", two hex digits make a byte, unpacked as "1;R".
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        let (w, h) = usize_size(self.size);
        let mut c = Canvas::new(Mode::One, w, h)?;
        let u = find(Mode::One, "1;R")?;
        let bytes = w.div_ceil(8);
        let mut row = vec![0u8; bytes.max(1)];
        let (mut x, mut y) = (0usize, 0usize);
        let d = self.data;
        let mut p = self.off;
        let hex = |v: u8| -> u8 {
            match v {
                b'0'..=b'9' => v - b'0',
                b'a'..=b'f' => v - b'a' + 10,
                b'A'..=b'F' => v - b'A' + 10,
                _ => 0,
            }
        };
        loop {
            while p < d.len() && d[p] != b'x' {
                p += 1;
            }
            if d.len().saturating_sub(p) < 3 {
                return Err(Raise::truncated());
            }
            row[x] = (hex(d[p + 1]) << 4).wrapping_add(hex(d[p + 2]));
            x += 1;
            if x >= bytes {
                c.unpack_row(&u, 0, y, &row, w);
                x = 0;
                y += 1;
                if y >= h {
                    return Ok(c);
                }
            }
            p += 3;
        }
    }
}

// ---------------------------------------------------------------- XPM

pub(crate) fn xpm_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"/* XPM */"))
}

/// `"([0-9]*) ([0-9]*) ([0-9]*) ([0-9]*)` matched at the start of a line.
fn xpm_head(line: &[u8]) -> Option<[i128; 4]> {
    let mut p = 0;
    if line.first() != Some(&b'"') {
        return None;
    }
    p += 1;
    let mut out = [0i128; 4];
    for (k, o) in out.iter_mut().enumerate() {
        let s = p;
        while p < line.len() && line[p].is_ascii_digit() {
            p += 1;
        }
        *o = py_int(&line[s..p]).unwrap_or(-1);
        if k < 3 {
            if line.get(p) != Some(&b' ') {
                return None;
            }
            p += 1;
        }
    }
    Some(out)
}

pub(crate) fn xpm_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(d);
    if !xpm_accept(f.read(9))? {
        return Err(Raise::syntax("not an XPM file"));
    }
    let m = loop {
        let line = f.readline();
        if line.is_empty() {
            return Err(Raise::syntax("broken XPM file"));
        }
        if let Some(m) = xpm_head(line) {
            break m;
        }
    };
    // int("") is a ValueError
    if m.iter().any(|&v| v < 0) {
        return Err(Raise::value("invalid literal for int()"));
    }
    let size = (m[0] as i64, m[1] as i64);
    let plen = m[2];
    let bpp = m[3] as usize;
    let mut has_trans = false;
    for _ in 0..plen {
        let line = rstrip(f.readline());
        let c_end = (bpp + 1).min(line.len());
        let body = if line.len() >= 2 && bpp < line.len() - 2 {
            &line[bpp + 1..line.len() - 2]
        } else {
            &[][..]
        };
        let _ = c_end;
        let toks: Vec<&[u8]> = body
            .split(|c| c.is_ascii_whitespace())
            .filter(|t| !t.is_empty())
            .collect();
        let mut done = false;
        let mut i = 0;
        while i < toks.len() {
            if toks[i] == b"c" {
                let rgb = toks.get(i + 1).ok_or_else(Raise::index_error)?;
                if *rgb == b"None" {
                    has_trans = true;
                } else if rgb.starts_with(b"#") {
                    let h = std::str::from_utf8(&rgb[1..])
                        .ok()
                        .filter(|s| !s.is_empty());
                    let ok = h.is_some_and(|s| {
                        s.trim().chars().all(|c| c.is_ascii_hexdigit() || c == '_')
                    });
                    if !ok {
                        return Err(Raise::value("invalid literal for int() with base 16"));
                    }
                } else {
                    return Err(Raise::value("cannot read this XPM file"));
                }
                done = true;
                break;
            }
            i += 2;
        }
        if !done {
            return Err(Raise::value("cannot read this XPM file"));
        }
    }
    let mode = if plen > 256 {
        if has_trans { "RGBA" } else { "RGB" }
    } else {
        "P"
    };
    Ok(Opened::new("XPM", mode, size, Box::new(NoDecoder("XPM"))))
}

// ---------------------------------------------------------------- IMT

/// `([a-z]*) ([^ \r\n]*)` matched at the start.
fn imt_field(s: &[u8]) -> Option<(&[u8], &[u8])> {
    let k_end = s
        .iter()
        .position(|c| !c.is_ascii_lowercase())
        .unwrap_or(s.len());
    if s.get(k_end) != Some(&b' ') {
        return None;
    }
    let v = &s[k_end + 1..];
    let v_end = v
        .iter()
        .position(|&c| c == b' ' || c == b'\r' || c == b'\n')
        .unwrap_or(v.len());
    Some((&s[..k_end], &v[..v_end]))
}

pub(crate) fn imt_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(d);
    let mut buffer = f.read(100).to_vec();
    if !buffer.contains(&b'\n') {
        return Err(Raise::syntax("not an IM file"));
    }
    let (mut xsize, mut ysize) = (0i128, 0i128);
    let mut size: Option<(i128, i128)> = None;
    let mut mode = "";
    let mut tile_off = None;
    loop {
        let mut s: Vec<u8> = if !buffer.is_empty() {
            let c = buffer.remove(0);
            vec![c]
        } else {
            f.read(1).to_vec()
        };
        if s.is_empty() {
            break;
        }
        if s == b"\x0c" {
            tile_off = Some(f.tell() - buffer.len());
            break;
        }
        if !buffer.contains(&b'\n') {
            buffer.extend_from_slice(f.read(100));
        }
        let mut lines: Vec<Vec<u8>> = buffer.split(|&c| c == b'\n').map(|l| l.to_vec()).collect();
        s.extend_from_slice(&lines.remove(0));
        buffer = lines.join(&b'\n');
        if s.len() == 1 || s.len() > 100 {
            break;
        }
        if s[0] == b'*' {
            continue;
        }
        let Some((k, v)) = imt_field(&s) else { break };
        if k == b"width" {
            xsize = py_int(v).ok_or_else(|| Raise::value("invalid literal for int()"))?;
            size = Some((xsize, ysize));
        } else if k == b"height" {
            ysize = py_int(v).ok_or_else(|| Raise::value("invalid literal for int()"))?;
            size = Some((xsize, ysize));
        } else if k == b"pixel" && v == b"n8" {
            mode = "L";
        }
    }
    // without width or height lines the size is the default (0, 0)
    let size = size.map_or((0, 0), |(a, b)| (a as i64, b as i64));
    let load: Box<dyn Load> = match tile_off {
        Some(off) if mode == "L" => Box::new(RawLoad {
            data: d,
            mode: Mode::L,
            size: usize_size(size),
            tiles: vec![(off, "L".into(), 0, false)],
            palette: None,
        }),
        _ => Box::new(Fails(Raise::os("cannot load this image"))),
    };
    Ok(Opened::new("IMT", mode, size, load))
}

// ---------------------------------------------------------------- IPTC

pub(crate) fn iptc_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(d);
    let mut info: std::collections::HashMap<(u8, u8), Vec<Option<Vec<u8>>>> = Default::default();
    loop {
        let s = f.read(5);
        if s.iter().all(|&c| c == 0) {
            break;
        }
        let tag = (byte(s, 1)?, byte(s, 2)?);
        if s[0] != 0x1C || ![1, 2, 3, 4, 5, 6, 7, 8, 9, 240].contains(&tag.0) {
            return Err(Raise::syntax("invalid IPTC/NAA file"));
        }
        let sz = byte(s, 3)? as usize;
        let size = if sz > 132 {
            return Err(Raise::os("illegal field length in IPTC/NAA file"));
        } else if sz == 128 {
            0
        } else if sz > 128 {
            let b = f.read(sz - 128);
            let mut v = vec![0u8; 4];
            v.extend_from_slice(b);
            u32be(&v[v.len() - 4..], 0)? as usize
        } else {
            u16be(s, 3)? as usize
        };
        if tag == (8, 10) {
            break;
        }
        let data = if size > 0 {
            Some(f.read(size).to_vec())
        } else {
            None
        };
        info.entry(tag).or_default().push(data);
    }
    let first = |t: (u8, u8)| -> Result<Option<Vec<u8>>, Raise> {
        let v = info.get(&t).ok_or_else(Raise::key)?;
        Ok(v[0].clone())
    };
    let l = first((3, 60))?;
    let multi = info.get(&(3, 60)).is_some_and(|v| v.len() > 1);
    if multi {
        return Err(Raise::unsupported("IPTC with repeated fields"));
    }
    let l = l.ok_or_else(|| Raise::type_error("'NoneType' object is not subscriptable"))?;
    let layers = byte(&l, 0)?;
    let component = byte(&l, 1)?;
    let mode = if layers == 1 && component == 0 {
        "L"
    } else if layers == 3 && component != 0 {
        "RGB"
    } else if layers == 4 && component != 0 {
        "CMYK"
    } else {
        ""
    };
    let geti = |t: (u8, u8)| -> Result<i64, Raise> {
        let v = first(t)?.ok_or_else(|| Raise::type_error("can only concatenate bytes"))?;
        let mut b = vec![0u8; 4];
        b.extend_from_slice(&v);
        Ok(u32be(&b[b.len() - 4..], 0)? as i64)
    };
    let size = (geti((3, 20))?, geti((3, 30))?);
    let comp = geti((3, 120))?;
    if comp != 1 && comp != 5 {
        return Err(Raise::os("Unknown IPTC image compression"));
    }
    Ok(Opened::new("IPTC", mode, size, Box::new(NoDecoder("IPTC"))))
}

// ---------------------------------------------------------------- McIdas

pub(crate) fn mcidas_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"\x00\x00\x00\x00\x00\x00\x00\x04"))
}

pub(crate) fn mcidas_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let s = &d[..d.len().min(256)];
    if !mcidas_accept(s)? || s.len() != 256 {
        return Err(Raise::syntax("not an McIdas area file"));
    }
    let w = |i: usize| -> i64 { u32be(s, (i - 1) * 4).map_or(0, |v| v as i32 as i64) };
    let (mode, rawmode) = match w(11) {
        1 => ("L", "L"),
        2 => ("I;16B", "I;16B"),
        4 => ("I", "I;32B"),
        _ => return Err(Raise::syntax("unsupported McIdas format")),
    };
    let size = (w(10), w(9));
    let offset = w(34) + w(15);
    let stride = w(15) + w(10) * w(11) * w(14);
    let m = Mode::from_name(mode).ok_or_else(Raise::key)?;
    let load: Box<dyn Load> = if offset < 0 || stride < 0 {
        Box::new(Fails(Raise::value("Tile offset cannot be negative")))
    } else {
        Box::new(RawLoad {
            data: d,
            mode: m,
            size: usize_size(size),
            tiles: vec![(offset as usize, rawmode.into(), stride as usize, false)],
            palette: None,
        })
    };
    Ok(Opened::new("MCIDAS", mode, size, load))
}

// ---------------------------------------------------------------- PIXAR

pub(crate) fn pixar_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"\x80\xe8\x00\x00"))
}

pub(crate) fn pixar_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let s = &d[..d.len().min(512)];
    if !pixar_accept(s)? {
        return Err(Raise::syntax("not a PIXAR file"));
    }
    let size = (u16le(s, 418)? as i64, u16le(s, 416)? as i64);
    let m = (u16le(s, 424)?, u16le(s, 426)?);
    let mode = if m == (14, 2) { "RGB" } else { "" };
    Ok(Opened::new(
        "PIXAR",
        mode,
        size,
        Box::new(RawLoad {
            data: d,
            mode: Mode::Rgb,
            size: usize_size(size),
            tiles: vec![(1024, "RGB".into(), 0, false)],
            palette: None,
        }),
    ))
}

// ---------------------------------------------------------------- XV thumbnails

pub(crate) fn xvthumb_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"P7 332"))
}

pub(crate) fn xvthumb_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(d);
    if !xvthumb_accept(f.read(6))? {
        return Err(Raise::syntax("not an XV thumbnail file"));
    }
    f.readline();
    let s = loop {
        let s = f.readline();
        if s.is_empty() {
            return Err(Raise::syntax("Unexpected EOF reading XV thumbnail file"));
        }
        if s[0] != b'#' {
            break s;
        }
    };
    let toks: Vec<&[u8]> = s
        .split(|c| c.is_ascii_whitespace() || *c == 0x0b || *c == 0x0c)
        .filter(|t| !t.is_empty())
        .collect();
    if toks.len() < 2 {
        return Err(Raise::value("not enough values to unpack"));
    }
    let w = py_int(toks[0]).ok_or_else(|| Raise::value("invalid literal for int()"))? as i64;
    let h = py_int(toks[1]).ok_or_else(|| Raise::value("invalid literal for int()"))? as i64;
    let mut pal = Palette::default();
    let mut i = 0;
    for r in 0..8u32 {
        for g in 0..8u32 {
            for b in 0..4u32 {
                pal.rgba[i] = [
                    (r * 255 / 7) as u8,
                    (g * 255 / 7) as u8,
                    (b * 255 / 3) as u8,
                    255,
                ];
                i += 1;
            }
        }
    }
    let size = (w, h);
    Ok(Opened::new(
        "XVTHUMB",
        "P",
        size,
        Box::new(RawLoad {
            data: d,
            mode: Mode::P,
            size: usize_size(size),
            tiles: vec![(f.tell(), "P".into(), 0, false)],
            palette: Some(pal),
        }),
    ))
}

// ---------------------------------------------------------------- GIMP brush

pub(crate) fn gbr_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.len() >= 8 && u32be(p, 0)? >= 20 && [1, 2].contains(&u32be(p, 4)?))
}

pub(crate) fn gbr_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(d);
    let header = u32be(f.read(4), 0)? as i64;
    if header < 20 {
        return Err(Raise::syntax("not a GIMP brush"));
    }
    let version = u32be(f.read(4), 0)?;
    if version != 1 && version != 2 {
        return Err(Raise::syntax("Unsupported GIMP brush version"));
    }
    let w = u32be(f.read(4), 0)? as i64;
    let h = u32be(f.read(4), 0)? as i64;
    if w == 0 || h == 0 {
        return Err(Raise::syntax("not a GIMP brush"));
    }
    let depth = u32be(f.read(4), 0)?;
    if depth != 1 && depth != 4 {
        return Err(Raise::syntax("Unsupported GIMP brush color depth"));
    }
    let comment = if version == 1 {
        header - 20
    } else {
        if f.read(4) != b"GIMP" {
            return Err(Raise::syntax("not a GIMP brush, bad magic number"));
        }
        u32be(f.read(4), 0)?;
        header - 28
    };
    if comment > 0 {
        f.read(comment as usize);
    }
    let mode = if depth == 1 { "L" } else { "RGBA" };
    bomb_check((w, h))?;
    let off = f.tell();
    let m = Mode::from_name(mode).ok_or_else(Raise::key)?;
    Ok(Opened::new(
        "GBR",
        mode,
        (w, h),
        Box::new(GbrLoad {
            data: d,
            off,
            mode: m,
            size: (w, h),
        }),
    ))
}

struct GbrLoad<'a> {
    data: &'a [u8],
    off: usize,
    mode: Mode,
    size: (i64, i64),
}

impl Load for GbrLoad<'_> {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        let (w, h) = usize_size(self.size);
        let mut c = Canvas::new(self.mode, w, h)?;
        let bands = if self.mode == Mode::L { 1 } else { 4 };
        let n = w * h * bands;
        let d = self
            .data
            .get(self.off..(self.off + n).min(self.data.len()))
            .unwrap_or(&[]);
        let raw = if self.mode == Mode::L { "L" } else { "RGBA" };
        raw::set_as_raw(&mut c, d, find(self.mode, raw)?, 0, false)?;
        Ok(c)
    }
}

// ---------------------------------------------------------------- FTEX

pub(crate) fn ftex_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"FTEX"))
}

pub(crate) fn ftex_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(d);
    if !ftex_accept(f.read(4))? {
        return Err(Raise::syntax("not an FTEX file"));
    }
    u32le(f.read(4), 0)?;
    let b = f.read(8);
    let size = (u32le(b, 0)? as i32 as i64, u32le(b, 4)? as i32 as i64);
    let b = f.read(8);
    let (_mip, fmt_count) = (u32le(b, 0)?, u32le(b, 4)? as i32);
    if fmt_count != 1 {
        return Err(Raise::value("Unsupported number of texture formats"));
    }
    let b = f.read(8);
    let (fmt, wher) = (u32le(b, 0)? as i32, u32le(b, 4)? as i32);
    if wher < 0 {
        return Err(Raise::value("negative seek position"));
    }
    f.seek(wher as usize);
    let msize = u32le(f.read(4), 0)? as i32;
    if msize < -1 {
        return Err(Raise::value("read length must be non-negative or -1"));
    }
    let data_off = f.tell();
    match fmt {
        0 => Ok(Opened::new(
            "FTEX",
            "RGBA",
            size,
            Box::new(NoDecoder("FTEX DXT1")),
        )),
        1 => {
            let end = if msize < 0 {
                d.len()
            } else {
                (data_off + msize as usize).min(d.len())
            };
            let sub = d.get(data_off..end).unwrap_or(&[]);
            Ok(Opened::new(
                "FTEX",
                "RGB",
                size,
                Box::new(RawLoad {
                    data: sub,
                    mode: Mode::Rgb,
                    size: usize_size(size),
                    tiles: vec![(0, "RGB".into(), 0, false)],
                    palette: None,
                }),
            ))
        }
        _ => Err(Raise::value("Invalid texture compression format")),
    }
}

// ---------------------------------------------------------------- FLI

pub(crate) fn fli_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(
        p.len() >= 16
            && [0xAF11, 0xAF12].contains(&u16le(p, 4)?)
            && [0, 3].contains(&u16le(p, 14)?),
    )
}

/// FLI: the header checks of `_open`; the frame decoder is not ported.
pub(crate) fn fli_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let s = &d[..d.len().min(128)];
    let ok = fli_accept(s)?
        && s.get(20..22) == Some(&[0, 0][..])
        && s.get(42..80).is_some_and(|b| b.iter().all(|&c| c == 0))
        && s.get(88..).is_some_and(|b| b == [0u8; 40]);
    if !ok {
        return Err(Raise::syntax("not an FLI/FLC file"));
    }
    let size = (u16le(s, 8)? as i64, u16le(s, 10)? as i64);
    Ok(Opened::new("FLI", "P", size, Box::new(NoDecoder("FLI"))))
}

// ---------------------------------------------------------------- FITS, BLP, PCD, MPEG

pub(crate) fn fits_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"SIMPLE"))
}

/// FITS: approximated. A primary header "SIMPLE = T" with NAXIS1 and NAXIS2 and a BITPIX
/// Pillow reads opens; the data is not decoded.
pub(crate) fn fits_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(d);
    let mut naxis = [None, None];
    let mut bitpix = None;
    let mut first = true;
    loop {
        let h = f.read(80);
        if h.is_empty() {
            return Err(Raise::os("Truncated FITS file"));
        }
        let key = String::from_utf8_lossy(&h[..h.len().min(8)])
            .trim()
            .to_string();
        if key == "END" {
            break;
        }
        let val = h.get(8..).unwrap_or(&[]);
        let val = val.split(|&c| c == b'/').next().unwrap_or(&[]);
        let val = String::from_utf8_lossy(val)
            .trim()
            .trim_start_matches('=')
            .trim()
            .to_string();
        if first && (key != "SIMPLE" || val != "T") {
            return Err(Raise::syntax("Not a FITS file"));
        }
        first = false;
        match key.as_str() {
            "NAXIS1" => naxis[0] = py_int(val.as_bytes()),
            "NAXIS2" => naxis[1] = py_int(val.as_bytes()),
            "BITPIX" => bitpix = py_int(val.as_bytes()),
            _ => {}
        }
    }
    let (Some(w), Some(h)) = (naxis[0], naxis[1]) else {
        return Err(Raise::value("No image data"));
    };
    let mode = match bitpix {
        Some(8) => "L",
        Some(16) => "I;16B",
        Some(32) => "I",
        Some(-32) | Some(-64) => "F",
        _ => return Err(Raise::syntax("Unknown BITPIX")),
    };
    Ok(Opened::new(
        "FITS",
        mode,
        (w as i64, h as i64),
        Box::new(NoDecoder("FITS")),
    ))
}

pub(crate) fn blp_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"BLP1") || p.starts_with(b"BLP2"))
}

/// BLP: approximated from the header; not decoded.
pub(crate) fn blp_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let s = &d[..d.len().min(20)];
    if !blp_accept(s)? {
        return Err(Raise::syntax("not a BLP file"));
    }
    let comp = u32le(s, 4)?;
    let size = (u32le(s, 12)? as i64, u32le(s, 16)? as i64);
    if s.starts_with(b"BLP1") {
        let mode = if comp == 0 { "RGB" } else { "RGBA" };
        let _ = mode;
        return Ok(Opened::new("BLP", "RGB", size, Box::new(NoDecoder("BLP"))));
    }
    let alpha_depth = byte(s, 9)?;
    let mode = if alpha_depth != 0 { "RGBA" } else { "RGB" };
    Ok(Opened::new("BLP", mode, size, Box::new(NoDecoder("BLP"))))
}

pub(crate) fn pcd_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let s = d.get(2048..(2048 + 1539).min(d.len())).unwrap_or(&[]);
    if !s.starts_with(b"PCD_") {
        return Err(Raise::syntax("not a PCD file"));
    }
    let o = byte(s, 1538)? & 3;
    let size = if o == 1 || o == 3 {
        (512, 768)
    } else {
        (768, 512)
    };
    Ok(Opened::new("PCD", "RGB", size, Box::new(NoDecoder("PCD"))))
}

pub(crate) fn mpeg_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"\x00\x00\x01\xb3"))
}

pub(crate) fn mpeg_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    if d.len() < 4 || !mpeg_accept(d)? {
        return Err(Raise::syntax("not an MPEG file"));
    }
    // BitStream.read(12) twice: 3 bytes, IndexError when short
    let b = d.get(4..7).ok_or_else(Raise::index_error)?;
    let w = ((b[0] as i64) << 4) | (b[1] as i64 >> 4);
    let h = ((b[1] as i64 & 15) << 8) | b[2] as i64;
    Ok(Opened::new(
        "MPEG",
        "RGB",
        (w, h),
        Box::new(Fails(Raise::os("cannot load this image"))),
    ))
}

// ---------------------------------------------------------------- SPIDER

fn is_int(f: f64) -> bool {
    f.is_finite() && f.trunc() == f
}

fn spider_header(t: &[f64]) -> i64 {
    let h = |i: usize| t[i - 1];
    for i in [1, 2, 5, 12, 13, 22, 23] {
        if !is_int(h(i)) {
            return 0;
        }
    }
    let iform = h(5) as i64;
    if ![1, 3, -11, -12, -21, -22].contains(&iform) {
        return 0;
    }
    let (labrec, labbyt, lenbyt) = (h(13) as i64, h(22) as i64, h(23) as i64);
    if labbyt != labrec.wrapping_mul(lenbyt) {
        return 0;
    }
    labbyt
}

fn py_int_of(v: f64) -> Result<i64, Raise> {
    if v.is_nan() {
        return Err(Raise::value("cannot convert float NaN to integer"));
    }
    if v.is_infinite() {
        return Err(Raise::new(
            crate::Kind::OverflowError,
            "cannot convert float infinity to integer",
        ));
    }
    Ok(v.trunc() as i64)
}

pub(crate) fn spider_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    if d.len() < 108 {
        return Err(Raise::syntax("not a valid Spider file"));
    }
    let f = &d[..108];
    let read = |big: bool| -> Vec<f64> {
        f.chunks_exact(4)
            .map(|c| {
                let a = [c[0], c[1], c[2], c[3]];
                (if big {
                    f32::from_be_bytes(a)
                } else {
                    f32::from_le_bytes(a)
                }) as f64
            })
            .collect()
    };
    let mut big = true;
    let mut t = read(true);
    let mut hdrlen = spider_header(&t);
    if hdrlen == 0 {
        big = false;
        t = read(false);
        hdrlen = spider_header(&t);
    }
    if hdrlen == 0 {
        return Err(Raise::syntax("not a valid Spider file"));
    }
    let h = |i: usize| t[i - 1];
    if h(5) as i64 != 1 {
        return Err(Raise::syntax("not a Spider 2D image"));
    }
    let size = (h(12) as i64, h(2) as i64);
    let istack = py_int_of(h(24))?;
    let imgnumber = py_int_of(h(27))?;
    let offset = if istack == 0 && imgnumber == 0 {
        hdrlen
    } else if istack > 0 && imgnumber == 0 {
        py_int_of(h(26))?;
        hdrlen * 2
    } else if istack == 0 && imgnumber > 0 {
        return Err(Raise::new(
            crate::Kind::Other,
            "'SpiderImageFile' object has no attribute 'stkoffset'",
        ));
    } else {
        return Err(Raise::syntax("inconsistent stack header values"));
    };
    let rawmode = if big { "F;32BF" } else { "F;32F" };
    let load: Box<dyn Load> = if offset < 0 {
        Box::new(Fails(Raise::value("Tile offset cannot be negative")))
    } else {
        Box::new(RawLoad {
            data: d,
            mode: Mode::F,
            size: usize_size(size),
            tiles: vec![(offset as usize, rawmode.into(), 0, false)],
            palette: None,
        })
    };
    Ok(Opened::new("SPIDER", "F", size, load))
}
