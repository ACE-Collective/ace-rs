//! PpmImagePlugin: PBM, PGM, PPM (plain and raw), PFM and Pillow's "Py" variants.

use super::raw::{self, RawTile};
use crate::Raise;
use crate::image::{Canvas, Mode};
use crate::io::File;
use crate::open::{Load, Opened};
use crate::pyparse::{py_float, py_int};
use crate::unpack;

const SAFEBLOCK: usize = 1024 * 1024;

fn ws(c: u8) -> bool {
    matches!(c, 0x20 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d)
}

pub(crate) fn accept(prefix: &[u8]) -> Result<bool, Raise> {
    Ok(prefix.len() >= 2 && prefix[0] == b'P' && b"0123456fy".contains(&prefix[1]))
}

fn read_token(f: &mut File) -> Result<Vec<u8>, Raise> {
    let mut token = Vec::new();
    while token.len() <= 10 {
        let c = f.read(1);
        if c.is_empty() {
            break;
        }
        let c = c[0];
        if ws(c) {
            if token.is_empty() {
                continue;
            }
            break;
        } else if c == b'#' {
            loop {
                let d = f.read(1);
                if d.is_empty() || d[0] == b'\r' || d[0] == b'\n' {
                    break;
                }
            }
            continue;
        }
        token.push(c);
    }
    if token.is_empty() {
        return Err(Raise::value("Reached EOF while reading header"));
    }
    if token.len() > 10 {
        return Err(Raise::value("Token too long in file header"));
    }
    Ok(token)
}

fn int_token(f: &mut File) -> Result<i128, Raise> {
    let t = read_token(f)?;
    py_int(&t).ok_or_else(|| Raise::value("invalid literal for int()"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dec {
    Raw,
    Plain,
    Ppm,
}

pub(crate) fn open(data: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(data);
    let mut magic = Vec::new();
    for _ in 0..6 {
        let c = f.read(1);
        if c.is_empty() || ws(c[0]) {
            break;
        }
        magic.push(c[0]);
    }
    let mut mode = match &magic[..] {
        b"P1" | b"P4" => "1",
        b"P2" | b"P5" => "L",
        b"P3" | b"P6" => "RGB",
        b"P0CMYK" | b"PyCMYK" => "CMYK",
        b"Pf" => "F",
        b"PyP" => "P",
        b"PyRGBA" => "RGBA",
        _ => return Err(Raise::syntax("not a PPM file")),
    };
    let w = int_token(&mut f)?;
    let h = int_token(&mut f)?;
    let mut dec = if matches!(&magic[..], b"P1" | b"P2" | b"P3") {
        Dec::Plain
    } else {
        Dec::Raw
    };
    let rawmode: &'static str;
    let mut maxval = 0u32;
    let mut bottom_up = false;
    if mode == "1" {
        rawmode = "1;I";
    } else if mode == "F" {
        let t = read_token(&mut f)?;
        let scale =
            py_float(&t).ok_or_else(|| Raise::value("could not convert string to float"))?;
        if scale == 0.0 || !scale.is_finite() {
            return Err(Raise::value("scale must be finite and non-zero"));
        }
        rawmode = if scale < 0.0 { "F;32F" } else { "F;32BF" };
        bottom_up = true;
    } else {
        let mv = int_token(&mut f)?;
        if !(0 < mv && mv < 65536) {
            return Err(Raise::value(
                "maxval must be greater than 0 and less than 65536",
            ));
        }
        maxval = mv as u32;
        if maxval > 255 && mode == "L" {
            mode = "I";
        }
        let mut r = match mode {
            "L" => "L",
            "I" => "L",
            "RGB" => "RGB",
            "CMYK" => "CMYK",
            "P" => "P",
            _ => "RGBA",
        };
        if dec != Dec::Plain {
            if maxval == 65535 && mode == "I" {
                r = "I;16B";
            } else if maxval != 255 {
                dec = Dec::Ppm;
            }
        }
        rawmode = r;
    }
    let offset = f.tell();
    let size = (clamp(w), clamp(h));
    Ok(Opened::new(
        "PPM",
        mode,
        size,
        Box::new(PpmLoad {
            data,
            mode,
            rawmode,
            dec,
            maxval,
            bottom_up,
            offset,
            size,
        }),
    ))
}

fn clamp(v: i128) -> i64 {
    v.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

struct PpmLoad<'a> {
    data: &'a [u8],
    mode: &'static str,
    rawmode: &'static str,
    dec: Dec,
    maxval: u32,
    bottom_up: bool,
    offset: usize,
    size: (i64, i64),
}

fn bands(mode: &str) -> usize {
    match mode {
        "RGB" => 3,
        "CMYK" | "RGBA" => 4,
        _ => 1,
    }
}

impl Load for PpmLoad<'_> {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        let mode = Mode::from_name(self.mode).ok_or_else(Raise::key)?;
        let (w, h) = (self.size.0 as usize, self.size.1 as usize);
        let mut c = Canvas::new(mode, w, h)?;
        let find = |m: Mode, r: &str| {
            unpack::find(m, r).ok_or_else(|| Raise::value("unknown raw mode for given image mode"))
        };
        match self.dec {
            Dec::Raw => {
                let u = find(mode, self.rawmode)?;
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
            }
            Dec::Ppm => {
                let mut f = File::new(self.data);
                f.seek(self.offset);
                let in_bytes = if self.maxval < 256 { 1 } else { 2 };
                let is_i = mode == Mode::I;
                let out_max = if is_i { 65535.0 } else { 255.0 };
                let nb = bands(self.mode);
                let dest = w * h * nb * if is_i { 4 } else { 1 };
                let mut out = Vec::new();
                while out.len() < dest {
                    let px = f.read(in_bytes * nb);
                    if px.len() < in_bytes * nb {
                        break;
                    }
                    for b in 0..nb {
                        let v = if in_bytes == 1 {
                            px[b] as f64
                        } else {
                            u16::from_be_bytes([px[b * 2], px[b * 2 + 1]]) as f64
                        };
                        let v = (v / self.maxval as f64 * out_max)
                            .round_ties_even()
                            .min(out_max) as u32;
                        if is_i {
                            out.extend_from_slice(&v.to_le_bytes());
                        } else {
                            out.push(v as u8);
                        }
                    }
                }
                let r = if is_i { "I;32" } else { self.mode };
                raw::set_as_raw(&mut c, &out, find(mode, r)?, 0, false)?;
            }
            Dec::Plain => {
                let mut p = Plain {
                    f: File::new(self.data),
                    comment_spans: false,
                };
                p.f.seek(self.offset);
                if mode == Mode::One {
                    let px = p.bitonal(w * h)?;
                    raw::set_as_raw(&mut c, &px, find(mode, "1;8")?, 0, false)?;
                } else {
                    let px = p.blocks(mode == Mode::I, bands(self.mode), w * h, self.maxval)?;
                    let r = if mode == Mode::I { "I;32" } else { self.mode };
                    raw::set_as_raw(&mut c, &px, find(mode, r)?, 0, false)?;
                }
            }
        }
        Ok(c)
    }
}

/// PpmPlainDecoder.
struct Plain<'a> {
    f: File<'a>,
    comment_spans: bool,
}

fn find_from(b: &[u8], c: u8, start: usize) -> i64 {
    b.get(start..)
        .and_then(|s| s.iter().position(|&x| x == c))
        .map_or(-1, |i| (i + start) as i64)
}

fn comment_end(b: &[u8], start: usize) -> i64 {
    let a = find_from(b, b'\n', start);
    let c = find_from(b, b'\r', start);
    if a * c > 0 { a.min(c) } else { a.max(c) }
}

impl Plain<'_> {
    fn block(&mut self) -> Vec<u8> {
        self.f.read(SAFEBLOCK).to_vec()
    }

    fn ignore_comments(&mut self, mut block: Vec<u8>) -> Vec<u8> {
        if self.comment_spans {
            while !block.is_empty() {
                let e = comment_end(&block, 0);
                if e != -1 {
                    block = block[e as usize + 1..].to_vec();
                    break;
                }
                block = self.block();
            }
        }
        self.comment_spans = false;
        loop {
            let s = find_from(&block, b'#', 0);
            if s == -1 {
                break;
            }
            let e = comment_end(&block, s as usize);
            if e != -1 {
                let mut nb = block[..s as usize].to_vec();
                nb.extend_from_slice(&block[e as usize + 1..]);
                block = nb;
            } else {
                block.truncate(s as usize);
                self.comment_spans = true;
                break;
            }
        }
        block
    }

    fn bitonal(&mut self, total: usize) -> Result<Vec<u8>, Raise> {
        let mut data: Vec<u8> = Vec::new();
        while data.len() != total {
            let block = self.block();
            if block.is_empty() {
                break;
            }
            let block = self.ignore_comments(block);
            let tokens: Vec<u8> = block.into_iter().filter(|&c| !ws(c)).collect();
            if tokens.iter().any(|&t| t != b'0' && t != b'1') {
                return Err(Raise::value("Invalid token for this mode"));
            }
            data.extend_from_slice(&tokens);
            data.truncate(total);
        }
        Ok(data
            .into_iter()
            .map(|c| if c == b'0' { 0xff } else { 0 })
            .collect())
    }

    fn blocks(
        &mut self,
        is_i: bool,
        nb: usize,
        pixels: usize,
        maxval: u32,
    ) -> Result<Vec<u8>, Raise> {
        let max_len = 10;
        let out_bytes = if is_i { 4 } else { 1 };
        let out_max = if is_i { 65535.0 } else { 255.0 };
        let total = pixels * nb * out_bytes;
        let mut data = Vec::new();
        let mut half: Vec<u8> = Vec::new();
        while data.len() != total {
            let mut block = self.block();
            if block.is_empty() {
                if !half.is_empty() {
                    block = b" ".to_vec();
                } else {
                    break;
                }
            }
            let mut block = self.ignore_comments(block);
            if !half.is_empty() {
                let mut b = std::mem::take(&mut half);
                b.extend_from_slice(&block);
                block = b;
            }
            let mut tokens: Vec<&[u8]> =
                block.split(|&c| ws(c)).filter(|t| !t.is_empty()).collect();
            if !block.is_empty() && !ws(block[block.len() - 1]) {
                let t = tokens.pop().unwrap_or_default();
                if t.len() > max_len {
                    return Err(Raise::value("Token too long found in data"));
                }
                half = t.to_vec();
            }
            for t in tokens {
                if t.len() > max_len {
                    return Err(Raise::value("Token too long found in data"));
                }
                let v = py_int(t).ok_or_else(|| Raise::value("invalid literal for int()"))?;
                if v < 0 {
                    return Err(Raise::value("Channel value is negative"));
                }
                if v > maxval as i128 {
                    return Err(Raise::value("Channel value too large for this mode"));
                }
                let v = (v as f64 / maxval as f64 * out_max).round_ties_even() as u32;
                if is_i {
                    data.extend_from_slice(&v.to_le_bytes());
                } else {
                    data.push(v as u8);
                }
                if data.len() == total {
                    break;
                }
            }
        }
        Ok(data)
    }
}
