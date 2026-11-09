//! IcoImagePlugin and CurImagePlugin. ICO decodes its image inside `_open`, so a broken
//! icon fails `Image.open` itself.

use super::bmp::{self, BmpLoad};
use super::png;
use crate::Raise;
use crate::image::{Canvas, Mode, Palette};
use crate::io::{File, byte, u16le, u32le};
use crate::open::{Load, Opened, bomb_check, check_identified};
use crate::unpack;

pub(crate) fn accept(prefix: &[u8]) -> Result<bool, Raise> {
    Ok(prefix.starts_with(b"\0\0\x01\0"))
}

pub(crate) fn cur_accept(prefix: &[u8]) -> Result<bool, Raise> {
    Ok(prefix.starts_with(b"\0\0\x02\0"))
}

/// A decoded image, for formats that decode inside `_open`.
pub(crate) struct Ready(pub(crate) Canvas);

impl Load for Ready {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        Ok(self.0)
    }
}

#[derive(Clone)]
struct Entry {
    dim: (i64, i64),
    bpp: u16,
    size: u32,
    offset: u32,
    color_depth: f64,
}

/// The RGBA a pixel of an "1", "L", "P", "RGB" or "RGBA" image converts to.
fn to_rgba(mode: Mode, p: &[u8], pal: &Palette) -> [u8; 4] {
    match mode {
        Mode::One => {
            let v = if p[0] != 0 { 255 } else { 0 };
            [v, v, v, 255]
        }
        Mode::L => [p[0], p[0], p[0], 255],
        Mode::P => pal.rgba[p[0] as usize],
        Mode::Rgb => [p[0], p[1], p[2], 255],
        _ => [p[0], p[1], p[2], p[3]],
    }
}

pub(crate) fn open(data: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(data);
    let s = f.read(6);
    if !accept(s)? {
        return Err(Raise::syntax("not an ICO file"));
    }
    let n = u16le(s, 4)?;
    let mut entries = Vec::new();
    for _ in 0..n {
        let s = f.read(16);
        let w = byte(s, 0)?;
        let width = if w == 0 { 256 } else { w as i64 };
        let h = byte(s, 1)?;
        let height = if h == 0 { 256 } else { h as i64 };
        let nb_color = byte(s, 2)?;
        byte(s, 3)?;
        let _planes = u16le(s, 4)?;
        let bpp = u16le(s, 6)?;
        let size = u32le(s, 8)?;
        let offset = u32le(s, 12)?;
        let color_depth = if bpp != 0 {
            bpp as f64
        } else if nb_color != 0 && (nb_color as f64).log(2.0).ceil() != 0.0 {
            (nb_color as f64).log(2.0).ceil()
        } else {
            256.0
        };
        entries.push(Entry {
            dim: (width, height),
            bpp,
            size,
            offset,
            color_depth,
        });
    }
    entries.sort_by(|a, b| a.color_depth.total_cmp(&b.color_depth));
    entries.sort_by_key(|e| std::cmp::Reverse(e.dim.0 * e.dim.1));
    let first = entries.first().ok_or_else(Raise::index_error)?.clone();
    let canvas = frame(data, &first)?;
    let mode = canvas.mode.name();
    let size = (canvas.w as i64, canvas.h as i64);
    Ok(Opened::new("ICO", mode, size, Box::new(Ready(canvas))))
}

/// `IcoFile.frame(idx)` and the load that follows.
fn frame(data: &[u8], e: &Entry) -> Result<Canvas, Raise> {
    let off = e.offset as usize;
    if data.get(off..off + 8) == Some(b"\x89PNG\r\n\x1a\n") {
        let im = png::open_at(data, off)?;
        check_identified(&im)?;
        bomb_check(im.size)?;
        return im.loader.load();
    }
    let mut f = File::new(data);
    f.seek(off);
    let mut b = bmp::bitmap(&mut f, 0, 0)?;
    if b.mode.is_empty() || b.size.0.min(b.size.1) <= 0 {
        return Err(Raise::syntax("not identified by this driver"));
    }
    bomb_check(b.size)?;
    let full_h = b.size.1;
    let w = b.size.0;
    let h = (full_h as f64 / 2.0) as i64;
    b.size = (w, h);
    let o = b.offset;
    // The mask, read before the image is loaded (as Image.frombuffer does).
    let (wu, hu) = (w as usize, h.max(0) as usize);
    let mut alpha = vec![0u8; wu * hu];
    if e.bpp == 32 {
        let mut f = File::new(data);
        f.seek(o);
        let raw = f.read(wu * hu * 4);
        let bytes: Vec<u8> = raw.iter().skip(3).step_by(4).copied().collect();
        if bytes.len() < wu * hu {
            return Err(Raise::value("buffer is not large enough"));
        }
        // ("L", 0, -1): bottom-up rows
        for y in 0..hu {
            alpha[(hu - 1 - y) * wu..(hu - y) * wu].copy_from_slice(&bytes[y * wu..(y + 1) * wu]);
        }
    } else {
        let mut wm = w;
        if wm % 32 > 0 {
            wm += 32 - (w % 32);
        }
        let total = ((wm * h) as f64 / 8.0) as i64;
        let and_off = e.offset as i64 + e.size as i64 - total;
        if and_off < 0 {
            return Err(Raise::value("negative seek value"));
        }
        let mut f = File::new(data);
        f.seek(and_off as usize);
        let mask = f.read(total.max(0) as usize);
        let stride = (wm as f64 / 8.0) as usize;
        let u = unpack::find(Mode::One, "1;I").expect("1;I");
        let mut m = Canvas::new(Mode::L, wu, hu)?;
        let t = super::raw::RawTile {
            x0: 0,
            y0: 0,
            x1: wu,
            y1: hu,
            offset: 0,
            u,
            stride,
            bottom_up: true,
        };
        // Unpacked as "1" (0 or 255), which is the alpha value putalpha takes.
        if !super::raw::decode(&mut m, mask, &t)? {
            return Err(Raise::value("not enough image data"));
        }
        alpha = m.px;
    }
    let load = BmpLoad { data, b };
    let mut c = load.canvas()?;
    c.keep_native()?;
    load.decode(&mut c)?;
    let pal = c.palette.clone().unwrap_or_default();
    let nat = c.native.take().expect("native");
    let ps = c.mode.pixel_size();
    let mut out = Canvas::new(Mode::Rgba, wu, hu)?;
    for (i, p) in nat.chunks_exact(ps).enumerate() {
        let mut px = to_rgba(c.mode, p, &pal);
        px[3] = alpha[i];
        out.put(i % wu, i / wu, &px);
    }
    Ok(out)
}

pub(crate) fn cur_open(data: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(data);
    let s = f.read(6);
    if !cur_accept(s)? {
        return Err(Raise::syntax("not a CUR file"));
    }
    let mut m: &[u8] = &[];
    for _ in 0..u16le(s, 4)? {
        let s = f.read(16);
        if m.is_empty() || (byte(s, 0)? > byte(m, 0)? && byte(s, 1)? > byte(m, 1)?) {
            m = s;
        }
    }
    if m.is_empty() {
        return Err(Raise::type_error("No cursors were found"));
    }
    let header = u32le(m, 12)? as usize;
    let mut b = bmp::bitmap(&mut f, header, 0)?;
    let masked = matches!(b.mode, "1" | "L");
    let raw_mode = b.mode;
    let (w, full_h) = b.size;
    let h = full_h.div_euclid(2);
    if !masked {
        b.size = (w, h);
    }
    let mode = if masked { "LA" } else { b.mode };
    Ok(Opened::new(
        "CUR",
        mode,
        (w, h),
        Box::new(CurLoad {
            load: BmpLoad { data, b },
            masked,
            raw_mode,
        }),
    ))
}

struct CurLoad<'a> {
    load: BmpLoad<'a>,
    masked: bool,
    raw_mode: &'static str,
}

impl Load for CurLoad<'_> {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        if !self.masked {
            let mut c = self.load.canvas()?;
            self.load.decode(&mut c)?;
            return Ok(c);
        }
        let mut c = self.load.canvas()?;
        c.keep_native()?;
        self.load.decode(&mut c)?;
        let (w, full) = (c.w, c.h);
        let nh = full / 2;
        let nat = c.native.take().expect("native");
        let mut out = Canvas::new(Mode::LA, w, nh)?;
        for y in 0..nh {
            for x in 0..w {
                let and = nat[y * w + x];
                let xor = nat[(nh + y) * w + x];
                let l = if self.raw_mode == "1" {
                    if xor != 0 { 255 } else { 0 }
                } else {
                    xor
                };
                let px = if self.raw_mode == "1" {
                    // paste_mask_1 with the inverted mask: copy where the AND bit is 0
                    if and == 0 {
                        [l, l, l, 255]
                    } else {
                        [0, 0, 0, 0]
                    }
                } else {
                    let mk = 255 - and as u32;
                    let bl = |v: u32| -> u8 {
                        let t = v * mk + 128;
                        (((t >> 8) + t) >> 8) as u8
                    };
                    [bl(l as u32), bl(l as u32), bl(l as u32), bl(255)]
                };
                out.put(x, y, &px);
            }
        }
        Ok(out)
    }
}
