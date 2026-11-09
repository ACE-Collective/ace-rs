//! Pillow's image modes, the pixels a decoder writes, and their conversion to "L".
//!
//! A decoder writes rows in Pillow's in-memory layout for the image's mode (one byte a pixel
//! for "1", "L" and "P", two for the "I;16" modes, four for the rest). The canvas keeps one byte
//! a pixel: the gray value `_image_hash` would get from that pixel, or the palette index for
//! "P" and "PA", which is mapped through the palette at the end. Every step from a decoded
//! pixel to its gray value (the paste over white for "RGBA" and "LA", then `convert("L")`) works
//! on one pixel at a time, so it can run as each row arrives.

use crate::Raise;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Mode {
    One,
    L,
    P,
    LA,
    PA,
    La,
    Rgb,
    Rgba,
    Rgbx,
    RgbaPre,
    Cmyk,
    YCbCr,
    Lab,
    Hsv,
    I,
    F,
    I16,
    I16B,
}

impl Mode {
    /// Bytes a pixel in Pillow's memory layout.
    pub(crate) fn pixel_size(self) -> usize {
        match self {
            Mode::One | Mode::L | Mode::P => 1,
            Mode::I16 | Mode::I16B => 2,
            _ => 4,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Mode::One => "1",
            Mode::L => "L",
            Mode::P => "P",
            Mode::LA => "LA",
            Mode::PA => "PA",
            Mode::La => "La",
            Mode::Rgb => "RGB",
            Mode::Rgba => "RGBA",
            Mode::Rgbx => "RGBX",
            Mode::RgbaPre => "RGBa",
            Mode::Cmyk => "CMYK",
            Mode::YCbCr => "YCbCr",
            Mode::Lab => "LAB",
            Mode::Hsv => "HSV",
            Mode::I => "I",
            Mode::F => "F",
            Mode::I16 => "I;16",
            Mode::I16B => "I;16B",
        }
    }

    pub(crate) fn from_name(s: &str) -> Option<Mode> {
        Some(match s {
            "1" => Mode::One,
            "L" => Mode::L,
            "P" => Mode::P,
            "LA" => Mode::LA,
            "PA" => Mode::PA,
            "La" => Mode::La,
            "RGB" => Mode::Rgb,
            "RGBA" => Mode::Rgba,
            "RGBX" => Mode::Rgbx,
            "RGBa" => Mode::RgbaPre,
            "CMYK" => Mode::Cmyk,
            "YCbCr" => Mode::YCbCr,
            "LAB" => Mode::Lab,
            "HSV" => Mode::Hsv,
            "I" => Mode::I,
            "F" => Mode::F,
            "I;16" | "I;16L" => Mode::I16,
            "I;16B" => Mode::I16B,
            _ => return None,
        })
    }
}

fn l24(r: u8, g: u8, b: u8) -> u8 {
    ((r as u32 * 19595 + g as u32 * 38470 + b as u32 * 7471 + 0x8000) >> 16) as u8
}

fn div255(a: u32) -> u32 {
    let t = a + 128;
    ((t >> 8) + t) >> 8
}

/// `BLEND(mask, 255, in)`: Paste.c's blend of `in` over a white background.
fn over_white(a: u8, v: u8) -> u8 {
    let a = a as u32;
    div255(255 * (255 - a) + v as u32 * a) as u8
}

fn muldiv255(a: u32, b: u32) -> u32 {
    let t = a * b + 128;
    ((t >> 8) + t) >> 8
}

fn clip8(v: i32) -> u8 {
    v.clamp(0, 255) as u8
}

fn cmyk_to_l(p: &[u8]) -> u8 {
    let nk = 255 - p[3] as i32;
    let r = clip8(nk - muldiv255(p[0] as u32, nk as u32) as i32);
    let g = clip8(nk - muldiv255(p[1] as u32, nk as u32) as i32);
    let b = clip8(nk - muldiv255(p[2] as u32, nk as u32) as i32);
    l24(r, g, b)
}

/// The gray value of one pixel, or its palette index for "P" and "PA".
pub(crate) fn pixel_to_l(mode: Mode, p: &[u8]) -> u8 {
    match mode {
        Mode::One => {
            if p[0] != 0 {
                255
            } else {
                0
            }
        }
        Mode::L | Mode::P | Mode::PA | Mode::YCbCr => p[0],
        Mode::LA => over_white(p[3], p[0]),
        Mode::La => p[0],
        Mode::Rgb | Mode::Rgbx => l24(p[0], p[1], p[2]),
        Mode::Rgba => l24(
            over_white(p[3], p[0]),
            over_white(p[3], p[1]),
            over_white(p[3], p[2]),
        ),
        Mode::RgbaPre => {
            // "RGBa" has no direct conversion to "L"; Pillow goes through "RGB" (rgba2rgb_ ...
            // which for "RGBa" is the unpremultiplying rgbA2rgba then dropping alpha).
            let a = p[3] as u32;
            if a == 0 {
                0
            } else if a == 255 {
                l24(p[0], p[1], p[2])
            } else {
                let un = |v: u8| -> u8 { clip8(((v as u32 * 255 + a / 2) / a) as i32) };
                l24(un(p[0]), un(p[1]), un(p[2]))
            }
        }
        Mode::Cmyk => cmyk_to_l(p),
        Mode::Lab | Mode::Hsv => 0,
        Mode::I => {
            let v = i32::from_le_bytes([p[0], p[1], p[2], p[3]]);
            v.clamp(0, 255) as u8
        }
        Mode::F => {
            let v = f32::from_le_bytes([p[0], p[1], p[2], p[3]]);
            if v <= 0.0 {
                0
            } else if v >= 255.0 {
                255
            } else {
                v as u8
            }
        }
        Mode::I16 => {
            if p[1] != 0 {
                255
            } else {
                p[0]
            }
        }
        Mode::I16B => {
            if p[0] != 0 {
                255
            } else {
                p[1]
            }
        }
    }
}

/// A palette as Pillow's C core holds it: 256 RGBA entries, opaque black by default.
#[derive(Clone)]
pub(crate) struct Palette {
    pub(crate) rgba: [[u8; 4]; 256],
}

impl Default for Palette {
    fn default() -> Self {
        Palette {
            rgba: [[0, 0, 0, 255]; 256],
        }
    }
}

impl Palette {
    /// `im.putpalette("RGB", "RGB", data)` and the like: `bands` bytes an entry, `order`
    /// giving the byte of R, G and B within an entry. More than 256 entries is a ValueError.
    pub(crate) fn from_raw(data: &[u8], bands: usize, order: [usize; 3]) -> Result<Palette, Raise> {
        let n = data.len() * 8 / (bands * 8);
        if n > 256 {
            return Err(Raise::value("invalid palette size"));
        }
        let mut p = Palette::default();
        for i in 0..n {
            let e = &data[i * bands..i * bands + bands];
            p.rgba[i] = [e[order[0]], e[order[1]], e[order[2]], 255];
        }
        Ok(p)
    }

    pub(crate) fn lut(&self) -> [u8; 256] {
        let mut t = [0u8; 256];
        for (i, e) in self.rgba.iter().enumerate() {
            t[i] = l24(e[0], e[1], e[2]);
        }
        t
    }
}

/// The decoded image, one byte a pixel (see the module docs).
pub(crate) struct Canvas {
    pub(crate) mode: Mode,
    pub(crate) w: usize,
    pub(crate) h: usize,
    pub(crate) px: Vec<u8>,
    pub(crate) palette: Option<Palette>,
    /// Full pixels in memory layout, kept for decoders that write one band at a time.
    pub(crate) native: Option<Vec<u8>>,
    scratch: Vec<u8>,
}

impl Canvas {
    /// `Image.core.new(mode, size)`: zeroed memory.
    pub(crate) fn new(mode: Mode, w: usize, h: usize) -> Result<Canvas, Raise> {
        let zero = [0u8; 4];
        Canvas::filled(mode, w, h, &zero[..mode.pixel_size()])
    }

    /// `Image.core.fill(mode, size, color)` with the color in memory layout.
    pub(crate) fn filled(mode: Mode, w: usize, h: usize, pixel: &[u8]) -> Result<Canvas, Raise> {
        if matches!(mode, Mode::Lab | Mode::Hsv) {
            // Neither converts to "L" (nor to "RGB" in the C core): convert raises.
        }
        let n = w.checked_mul(h).ok_or_else(Raise::memory)?;
        if n > crate::MAX_CANVAS_PIXELS {
            return Err(Raise::memory());
        }
        let v = pixel_to_l(mode, pixel);
        Ok(Canvas {
            mode,
            w,
            h,
            px: vec![v; n],
            palette: None,
            native: None,
            scratch: Vec::new(),
        })
    }

    /// Keeps full pixels (zeroed) instead of gray values, for band-at-a-time decoders.
    pub(crate) fn keep_native(&mut self) -> Result<(), Raise> {
        let n = self
            .w
            .checked_mul(self.h)
            .and_then(|n| n.checked_mul(self.mode.pixel_size()))
            .ok_or_else(Raise::memory)?;
        self.native = Some(vec![0; n]);
        self.px = Vec::new();
        Ok(())
    }

    /// Unpacks `n` pixels of raw data into row `y` from column `x` (`state->shuffle`).
    pub(crate) fn unpack_row(
        &mut self,
        u: &crate::unpack::Unpacker,
        x: usize,
        y: usize,
        input: &[u8],
        n: usize,
    ) {
        if y >= self.h || x >= self.w {
            return;
        }
        let n = n.min(self.w - x);
        let ps = self.mode.pixel_size();
        if let Some(nat) = &mut self.native {
            let row = &mut nat[(y * self.w + x) * ps..(y * self.w + x + n) * ps];
            u.run(row, input, n);
            return;
        }
        let mut tmp = std::mem::take(&mut self.scratch);
        tmp.clear();
        tmp.resize(n * ps, 0);
        u.run(&mut tmp, input, n);
        self.put_row(x, y, &tmp, n);
        self.scratch = tmp;
    }

    /// Writes `n` pixels of one row, from `x`, given in memory layout. Pixels past the
    /// right edge are dropped.
    pub(crate) fn put_row(&mut self, x: usize, y: usize, row: &[u8], n: usize) {
        if y >= self.h || x >= self.w {
            return;
        }
        let ps = self.mode.pixel_size();
        let n = n.min(self.w - x).min(row.len() / ps);
        if let Some(nat) = &mut self.native {
            let start = (y * self.w + x) * ps;
            nat[start..start + n * ps].copy_from_slice(&row[..n * ps]);
            return;
        }
        let out = &mut self.px[y * self.w + x..y * self.w + x + n];
        let mode = self.mode;
        if ps == 1 && mode != Mode::One {
            out.copy_from_slice(&row[..n]);
            return;
        }
        for (i, o) in out.iter_mut().enumerate() {
            *o = pixel_to_l(mode, &row[i * ps..i * ps + ps]);
        }
    }

    /// Writes one pixel.
    pub(crate) fn put(&mut self, x: usize, y: usize, p: &[u8]) {
        if x < self.w && y < self.h {
            self.put_row(x, y, p, 1);
        }
    }

    /// `convert("L")` after the paste: maps palette indexes, and raises for the modes
    /// Pillow cannot convert.
    pub(crate) fn into_gray(mut self) -> Result<crate::resample::Gray, Raise> {
        if let Some(nat) = self.native.take() {
            let ps = self.mode.pixel_size();
            self.px = nat
                .chunks_exact(ps)
                .map(|p| pixel_to_l(self.mode, p))
                .collect();
        }
        match self.mode {
            Mode::Lab | Mode::Hsv => return Err(Raise::value("conversion not supported")),
            Mode::La => return Err(Raise::value("conversion not supported")),
            Mode::P | Mode::PA => {
                let lut = self.palette.take().unwrap_or_default().lut();
                for v in &mut self.px {
                    *v = lut[*v as usize];
                }
            }
            _ => {}
        }
        Ok(crate::resample::Gray {
            w: self.w,
            h: self.h,
            px: self.px,
        })
    }
}
