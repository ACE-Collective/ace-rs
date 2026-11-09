//! TgaImagePlugin. TGA has no accept check, so its `_open` runs on any file the earlier
//! plugins refused.

use super::raw::{self, RawTile};
use crate::Raise;
use crate::image::{Canvas, Mode, Palette};
use crate::io::{File, byte, u16le, u32le};
use crate::open::{Load, Opened};
use crate::unpack;

const MAXBLOCK: usize = 65536;

pub(crate) fn open(data: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(data);
    let s = f.read(18);
    let id_len = byte(s, 0)? as usize;
    let colormaptype = byte(s, 1)?;
    let imagetype = byte(s, 2)?;
    let depth = byte(s, 16)?;
    let flags = byte(s, 17)?;
    let size = (u16le(s, 12)? as i64, u16le(s, 14)? as i64);
    if colormaptype > 1 || size.0 <= 0 || size.1 <= 0 || ![1, 8, 16, 24, 32].contains(&depth) {
        return Err(Raise::syntax("not a TGA file"));
    }
    let mode = match imagetype {
        3 | 11 => match depth {
            1 => "1",
            16 => "LA",
            _ => "L",
        },
        1 | 9 => {
            if colormaptype != 0 {
                "P"
            } else {
                "L"
            }
        }
        2 | 10 => {
            if depth == 24 {
                "RGB"
            } else {
                "RGBA"
            }
        }
        _ => return Err(Raise::syntax("unknown TGA mode")),
    };
    let o = flags & 0x30;
    let flip_h = o == 0x10 || o == 0x30;
    let bottom_up = o == 0 || o == 0x10;
    if id_len > 0 {
        f.read(id_len);
    }
    let mut palette = None;
    if colormaptype != 0 {
        let (start, n, mapdepth) = (u16le(s, 3)? as usize, u16le(s, 5)? as usize, byte(s, 7)?);
        let (bpe, raw) = match mapdepth {
            16 => (2, "BGRA;15Z"),
            24 => (3, "BGR"),
            32 => (4, "BGRA"),
            _ => return Err(Raise::syntax("unknown TGA map depth")),
        };
        let mut p = vec![0u8; bpe * start];
        p.extend_from_slice(f.read(bpe * n));
        palette = Some((p, raw));
    }
    let rawmode = match (imagetype & 7, depth) {
        (1, 8) => Some("P"),
        (3, 1) => Some("1"),
        (3, 8) => Some("L"),
        (3, 16) => Some("LA"),
        (2, 16) => Some("BGRA;15Z"),
        (2, 24) => Some("BGR"),
        (2, 32) => Some("BGRA"),
        _ => None,
    };
    Ok(Opened::new(
        "TGA",
        mode,
        size,
        Box::new(TgaLoad {
            data,
            mode,
            size,
            rawmode,
            rle: imagetype & 8 != 0,
            depth: depth as usize,
            bottom_up,
            flip_h,
            offset: f.tell(),
            palette,
        }),
    ))
}

struct TgaLoad<'a> {
    data: &'a [u8],
    mode: &'static str,
    size: (i64, i64),
    rawmode: Option<&'static str>,
    rle: bool,
    depth: usize,
    bottom_up: bool,
    flip_h: bool,
    offset: usize,
    palette: Option<(Vec<u8>, &'static str)>,
}

fn palette_from(p: &[u8], raw: &str) -> Result<Palette, Raise> {
    let u = unpack::find(Mode::Rgba, raw).ok_or_else(|| Raise::value("bad palette mode"))?;
    let bpe = u.bits / 8;
    let n = p.len() / bpe;
    if n > 256 {
        return Err(Raise::value("invalid palette size"));
    }
    let mut out = vec![0u8; n * 4];
    u.run(&mut out, p, n);
    let mut pal = Palette::default();
    for i in 0..n {
        pal.rgba[i] = [out[i * 4], out[i * 4 + 1], out[i * 4 + 2], out[i * 4 + 3]];
    }
    Ok(pal)
}

impl Load for TgaLoad<'_> {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        let rawmode = self
            .rawmode
            .ok_or_else(|| Raise::os("cannot load this image"))?;
        let mode = Mode::from_name(self.mode).ok_or_else(Raise::key)?;
        let (w, h) = (self.size.0 as usize, self.size.1 as usize);
        let mut c = Canvas::new(mode, w, h)?;
        if let Some((p, raw)) = &self.palette {
            if mode == Mode::P {
                c.palette = Some(palette_from(p, raw)?);
            } else if mode == Mode::L {
                // Image.load puts the palette on the "L" core image, which becomes "P";
                // resize then raises ValueError("image has wrong mode").
                palette_from(p, raw)?;
                return Err(Raise::value("image has wrong mode"));
            }
        }
        let u = unpack::find(mode, rawmode)
            .ok_or_else(|| Raise::value("unknown raw mode for given image mode"))?;
        // RGBA with an extension area saying the alpha is undefined is filled opaque, and a
        // horizontal flip happens after decoding: both need the pixels kept whole.
        let mut fill_alpha = false;
        if mode == Mode::Rgba && self.data.len() >= 26 {
            let footer = &self.data[self.data.len() - 26..];
            if footer.ends_with(b"TRUEVISION-XFILE.\x00") {
                let ext = u32le(footer, 0)? as usize;
                if ext != 0 && self.data.get(ext + 494) == Some(&0) {
                    fill_alpha = true;
                }
            }
        }
        if fill_alpha || self.flip_h {
            c.keep_native()?;
        }
        if !self.rle {
            let mut t = [RawTile {
                x0: 0,
                y0: 0,
                x1: w,
                y1: h,
                offset: self.offset,
                u,
                stride: 0,
                bottom_up: self.bottom_up,
            }];
            raw::load_tiles(&mut c, self.data, &mut t)?;
        } else {
            rle(
                &mut c,
                self.data,
                self.offset,
                &u,
                self.depth / 8,
                self.bottom_up,
            )?;
        }
        if let Some(n) = &mut c.native {
            let ps = mode.pixel_size();
            if fill_alpha {
                for p in n.chunks_exact_mut(4) {
                    p[3] = 255;
                }
            }
            if self.flip_h {
                for row in n.chunks_exact_mut(w * ps) {
                    for x in 0..w / 2 {
                        for k in 0..ps {
                            row.swap(x * ps + k, (w - 1 - x) * ps + k);
                        }
                    }
                }
            }
        }
        Ok(c)
    }
}

/// TgaRleDecode.c, fed as ImageFile.load feeds it.
fn rle(
    c: &mut Canvas,
    data: &[u8],
    offset: usize,
    u: &unpack::Unpacker,
    depth: usize,
    bottom_up: bool,
) -> Result<(), Raise> {
    let (w, h) = (c.w, c.h);
    let bytes = u.row_bytes(w);
    let mut buffer = vec![0u8; bytes];
    let mut x = 0usize;
    let mut y: i64 = if bottom_up { h as i64 - 1 } else { 0 };
    let step: i64 = if bottom_up { -1 } else { 1 };
    let mut f = File::new(data);
    f.seek(offset);
    let mut b: Vec<u8> = Vec::new();
    loop {
        let s = f.read(MAXBLOCK);
        if s.is_empty() {
            return Err(Raise::truncated());
        }
        b.extend_from_slice(s);
        let mut p = 0usize;
        loop {
            if b.len() - p < 1 {
                break;
            }
            let mut n = depth * ((b[p] & 0x7f) as usize + 1);
            let mut extra = 0usize;
            if b[p] & 0x80 != 0 {
                if b.len() - p < 1 + depth {
                    break;
                }
                if x + n > bytes {
                    return Err(Raise::decoder(-1));
                }
                let mut i = 0;
                while i < n {
                    buffer[x + i..x + i + depth].copy_from_slice(&b[p + 1..p + 1 + depth]);
                    i += depth;
                }
                p += 1 + depth;
            } else {
                if b.len() - p < 1 + n {
                    break;
                }
                if x + n > bytes {
                    extra = n;
                    n = bytes - x;
                    extra -= n;
                }
                buffer[x..x + n].copy_from_slice(&b[p + 1..p + 1 + n]);
                p += 1 + n;
            }
            loop {
                x += n;
                if x >= bytes {
                    c.unpack_row(u, 0, y as usize, &buffer, w);
                    x = 0;
                    y += step;
                    if y < 0 || y >= h as i64 {
                        return Ok(());
                    }
                }
                if extra == 0 || x > 0 {
                    break;
                }
                n = extra.min(bytes);
                buffer[x..x + n].copy_from_slice(&b[p..p + n]);
                p += n;
                extra -= n;
            }
        }
        b.drain(..p);
    }
}
