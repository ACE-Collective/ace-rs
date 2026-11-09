//! BmpImagePlugin: BMP and DIB (and the bitmaps inside ICO and CUR files).

use super::raw::{self, RawTile};
use crate::Raise;
use crate::image::{Canvas, Mode, Palette};
use crate::io::{File, byte, u16le, u32le};
use crate::open::{Load, Opened};
use crate::unpack;

pub(crate) fn accept(prefix: &[u8]) -> Result<bool, Raise> {
    Ok(prefix.starts_with(b"BM"))
}

pub(crate) fn dib_accept(prefix: &[u8]) -> Result<bool, Raise> {
    Ok([12, 40, 52, 56, 64, 108, 124].contains(&u32le(prefix, 0)?))
}

/// What `_bitmap` sets up.
pub(crate) struct Bitmap {
    pub(crate) mode: &'static str,
    pub(crate) size: (i64, i64),
    pub(crate) raw_mode: &'static str,
    pub(crate) rle: Option<bool>,
    pub(crate) stride: usize,
    pub(crate) bottom_up: bool,
    pub(crate) offset: usize,
    /// The palette bytes and their padding (3 or 4), for mode "P".
    pub(crate) palette: Option<(Vec<u8>, usize)>,
}

/// `BmpImageFile._bitmap(header, offset)`.
pub(crate) fn bitmap(f: &mut File, header: usize, mut offset: usize) -> Result<Bitmap, Raise> {
    if header != 0 {
        f.seek(header);
    }
    let header_size = u32le(f.read(4), 0)? as usize;
    let hd = f.safe_read(header_size.saturating_sub(4))?;
    let (width, height, bits, compression, colors_hdr, padding, direction_up);
    let mut masks = None;
    if header_size == 12 {
        width = u16le(hd, 0)? as i64;
        height = u16le(hd, 2)? as i64;
        let _planes = u16le(hd, 4)?;
        bits = u16le(hd, 6)? as u32;
        compression = 0u32;
        colors_hdr = 0u64;
        padding = 3usize;
        direction_up = false;
    } else if [40, 52, 56, 64, 108, 124].contains(&header_size) {
        let y_flip = byte(hd, 7)? == 0xFF;
        direction_up = y_flip;
        width = u32le(hd, 0)? as i64;
        let h = u32le(hd, 4)? as i64;
        height = if y_flip { (1i64 << 32) - h } else { h };
        let _planes = u16le(hd, 8)?;
        bits = u16le(hd, 10)? as u32;
        compression = u32le(hd, 12)?;
        let _data_size = u32le(hd, 16)?;
        let _ppm = (u32le(hd, 20)?, u32le(hd, 24)?);
        colors_hdr = u32le(hd, 28)? as u64;
        padding = 4;
        if compression == 3 {
            let mut m = [0u32; 4];
            if hd.len() >= 48 {
                for (i, v) in m
                    .iter_mut()
                    .enumerate()
                    .take(if hd.len() >= 52 { 4 } else { 3 })
                {
                    *v = u32le(hd, 36 + i * 4)?;
                }
            } else {
                for v in m.iter_mut().take(3) {
                    *v = u32le(f.read(4), 0)?;
                }
            }
            masks = Some(m);
        }
    } else {
        return Err(Raise::os(format!(
            "Unsupported BMP header type ({header_size})"
        )));
    }
    // colors: 1 << bits when the header gives none (Python's integers do not overflow).
    let colors: u128 = if colors_hdr != 0 {
        colors_hdr as u128
    } else if bits < 100 {
        1u128 << bits
    } else {
        u128::MAX
    };
    if offset == 14 + header_size && bits <= 8 {
        offset += padding * colors as usize;
    }
    let (mut mode, mut raw_mode) = match bits {
        1 => ("P", "P;1"),
        4 => ("P", "P;4"),
        8 => ("P", "P"),
        16 => ("RGB", "BGR;15"),
        24 => ("RGB", "BGR"),
        32 => ("RGB", "BGRX"),
        _ => return Err(Raise::os(format!("Unsupported BMP pixel depth ({bits})"))),
    };
    let mut rle = None;
    match compression {
        3 => {
            let m = masks.expect("bitfields");
            let rgba = (m[0], m[1], m[2], m[3]);
            let rgb = (m[0], m[1], m[2]);
            raw_mode = match (bits, rgba, rgb) {
                (32, (0xFF0000, 0xFF00, 0xFF, 0x0), _) => "BGRX",
                (32, (0xFF000000, 0xFF0000, 0xFF00, 0x0), _) => "XBGR",
                (32, (0xFF000000, 0xFF00, 0xFF, 0x0), _) => "BGXR",
                (32, (0xFF000000, 0xFF0000, 0xFF00, 0xFF), _) => "ABGR",
                (32, (0xFF, 0xFF00, 0xFF0000, 0xFF000000), _) => "RGBA",
                (32, (0xFF0000, 0xFF00, 0xFF, 0xFF000000), _) => "BGRA",
                (32, (0xFF000000, 0xFF00, 0xFF, 0xFF0000), _) => "BGAR",
                (32, (0x0, 0x0, 0x0, 0x0), _) => "BGRA",
                (24, _, (0xFF0000, 0xFF00, 0xFF)) => "BGR",
                (16, _, (0xF800, 0x7E0, 0x1F)) => "BGR;16",
                (16, _, (0x7C00, 0x3E0, 0x1F)) => "BGR;15",
                _ => return Err(Raise::os("Unsupported BMP bitfields layout")),
            };
            if bits == 32 && raw_mode.contains('A') {
                mode = "RGBA";
            }
        }
        0 => {
            if bits == 32 && header == 22 {
                raw_mode = "BGRA";
                mode = "RGBA";
            }
        }
        1 | 2 => rle = Some(compression == 2),
        _ => {
            return Err(Raise::os(format!(
                "Unsupported BMP compression ({compression})"
            )));
        }
    }
    let mut palette = None;
    if mode == "P" {
        if !(colors > 0 && colors <= 65536) {
            return Err(Raise::os(format!(
                "Unsupported BMP Palette size ({colors})"
            )));
        }
        let colors = colors as usize;
        let pal = f.read(padding * colors);
        let mut grayscale = true;
        let indices: Vec<usize> = if colors == 2 {
            vec![0, 255]
        } else {
            (0..colors).collect()
        };
        for (ind, val) in indices.iter().enumerate() {
            let start = (ind * padding).min(pal.len());
            let end = (ind * padding + 3).min(pal.len());
            let v = (*val & 255) as u8;
            if pal[start..end] != [v, v, v] {
                grayscale = false;
            }
        }
        if grayscale {
            mode = if colors <= 2 { "1" } else { "L" };
            raw_mode = mode;
        } else {
            palette = Some((pal.to_vec(), padding));
        }
    }
    let stride = if rle.is_none() {
        ((((width as u128) * bits as u128 + 31) >> 3) & !3u128).min(usize::MAX as u128) as usize
    } else {
        0
    };
    let offset = if offset != 0 { offset } else { f.tell() };
    Ok(Bitmap {
        mode,
        size: (width, height),
        raw_mode,
        rle,
        stride,
        bottom_up: !direction_up,
        offset,
        palette,
    })
}

pub(crate) fn open_bmp(data: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(data);
    let head = f.read(14);
    if !head.starts_with(b"BM") {
        return Err(Raise::syntax("Not a BMP file"));
    }
    let offset = u32le(head, 10)? as usize;
    let b = bitmap(&mut f, 0, offset)?;
    Ok(opened("BMP", data, b))
}

pub(crate) fn open_dib(data: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(data);
    let b = bitmap(&mut f, 0, 0)?;
    Ok(opened("DIB", data, b))
}

fn opened<'a>(format: &'static str, data: &'a [u8], b: Bitmap) -> Opened<'a> {
    Opened::new(format, b.mode, b.size, Box::new(BmpLoad { data, b }))
}

pub(crate) struct BmpLoad<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) b: Bitmap,
}

impl BmpLoad<'_> {
    pub(crate) fn canvas(&self) -> Result<Canvas, Raise> {
        let mode = Mode::from_name(self.b.mode).ok_or_else(Raise::key)?;
        let mut c = Canvas::new(mode, self.b.size.0 as usize, self.b.size.1 as usize)?;
        if let Some((p, pad)) = &self.b.palette {
            let n = p.len() / pad;
            if n > 256 {
                return Err(Raise::value("invalid palette size"));
            }
            c.palette = Some(Palette::from_raw(p, *pad, [2, 1, 0])?);
        }
        Ok(c)
    }

    pub(crate) fn decode(&self, c: &mut Canvas) -> Result<(), Raise> {
        let b = &self.b;
        let mode = c.mode;
        match b.rle {
            None => {
                let u = unpack::find(mode, b.raw_mode)
                    .ok_or_else(|| Raise::value("unknown raw mode for given image mode"))?;
                let mut tiles = [RawTile {
                    x0: 0,
                    y0: 0,
                    x1: c.w,
                    y1: c.h,
                    offset: b.offset,
                    u,
                    stride: b.stride,
                    bottom_up: b.bottom_up,
                }];
                raw::load_tiles(c, self.data, &mut tiles)
            }
            Some(rle4) => {
                raw::check_extents(c, 0, 0, c.w as i64, c.h as i64)?;
                let px = rle_decode(self.data, b.offset, rle4, c.w, c.h);
                let raw_mode = if matches!(b.mode, "1" | "L") {
                    "L"
                } else {
                    "P"
                };
                let u =
                    unpack::find(mode, raw_mode).ok_or_else(|| Raise::value("unknown raw mode"))?;
                raw::set_as_raw(c, &px, u, 0, b.bottom_up)
            }
        }
    }
}

impl Load for BmpLoad<'_> {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        let mut c = self.canvas()?;
        self.decode(&mut c)?;
        Ok(c)
    }
}

/// BmpRleDecoder.decode: the pixel bytes it hands to `set_as_raw`.
fn rle_decode(data: &[u8], offset: usize, rle4: bool, xsize: usize, ysize: usize) -> Vec<u8> {
    let mut f = File::new(data);
    f.seek(offset);
    let mut out: Vec<u8> = Vec::new();
    let mut x = 0usize;
    let dest = xsize * ysize;
    while out.len() < dest {
        let pixels = f.read(1);
        let byte = f.read(1);
        if pixels.is_empty() || byte.is_empty() {
            break;
        }
        let mut num = pixels[0] as usize;
        let b = byte[0];
        if num != 0 {
            if x + num > xsize {
                num = xsize.saturating_sub(x);
            }
            if rle4 {
                for i in 0..num {
                    out.push(if i % 2 == 0 { b >> 4 } else { b & 0x0f });
                }
            } else {
                out.extend(std::iter::repeat_n(b, num));
            }
            x += num;
        } else if b == 0 {
            while !out.len().is_multiple_of(xsize) {
                out.push(0);
            }
            x = 0;
        } else if b == 1 {
            break;
        } else if b == 2 {
            let r = f.read(2);
            if r.len() < 2 {
                break;
            }
            let n = (dest - out.len()).min(r[0] as usize + r[1] as usize * xsize);
            out.extend(std::iter::repeat_n(0, n));
            x = out.len() % xsize;
        } else {
            let count = (dest - out.len()).min(b as usize);
            let byte_count;
            let got;
            if rle4 {
                byte_count = count.div_ceil(2);
                let r = f.read(byte_count);
                got = r.len();
                for (i, v) in r.iter().enumerate() {
                    out.push(v >> 4);
                    if i * 2 + 1 < count {
                        out.push(v & 0x0f);
                    }
                }
            } else {
                byte_count = count;
                let r = f.read(byte_count);
                got = r.len();
                out.extend_from_slice(r);
            }
            if got < byte_count || out.len() == dest {
                break;
            }
            x += b as usize;
            if f.tell() % 2 != 0 {
                f.skip(1);
            }
        }
    }
    out
}
