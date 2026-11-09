//! ImImagePlugin (IFUNC Image Memory). It has no accept check, so its header parser runs on
//! every file the earlier plugins refused.

use super::raw::{self, RawTile};
use crate::Raise;
use crate::image::{Canvas, Mode, Palette};
use crate::io::File;
use crate::open::{Load, NoDecoder, Opened};
use crate::pyparse::{py_float, py_int};
use crate::unpack;

const TAGS: [&str; 9] = [
    "Comment",
    "Date",
    "Digitalization equipment",
    "File size (no of images)",
    "Lut",
    "Name",
    "Scale (x,y)",
    "Image size (x*y)",
    "Image type",
];

fn open_info(v: &str) -> Option<(&'static str, String)> {
    let r: (&str, &str) = match v {
        "0 1 image" | "L 1 image" | "B1 image" => ("1", "1"),
        "Greyscale image" | "Grayscale image" => ("L", "L"),
        "RGB image" => ("RGB", "RGB;L"),
        "RLB image" | "RYB image" => ("RGB", "RLB"),
        "B2 image" => ("P", "P;2"),
        "B4 image" => ("P", "P;4"),
        "X 24 image" => ("RGB", "RGB"),
        "L 32 S image" => ("I", "I;32"),
        "L 32 F image" => ("F", "F;32"),
        "RGB3 image" => ("RGB", "RGB;T"),
        "RYB3 image" => ("RGB", "RYB;T"),
        "LA image" => ("LA", "LA;L"),
        "PA image" => ("LA", "PA;L"),
        "RGBA image" => ("RGBA", "RGBA;L"),
        "RGBX image" => ("RGB", "RGBX;L"),
        "CMYK image" => ("CMYK", "CMYK;L"),
        "YCC image" => ("YCbCr", "YCbCr;L"),
        _ => {
            let body = v.strip_suffix(" image")?;
            if let Some(i) = body.strip_prefix("L ") {
                return match i {
                    "16" | "16L" | "16B" => Some((leak16(i), format!("I;{i}"))),
                    "32S" => Some(("I", "I;32S".into())),
                    "8" | "8S" | "16S" | "32" | "32F" => Some(("F", format!("F;{i}"))),
                    _ => None,
                };
            }
            let i = body.strip_prefix("L*")?;
            if let Ok(j) = i.parse::<u32>() {
                if (2..33).contains(&j) && i == j.to_string() {
                    return Some(("F", format!("F;{j}")));
                }
            }
            return match i {
                "16L" | "16B" => Some((leak16(i), format!("I;{i}"))),
                "32S" => Some(("I", "I;32S".into())),
                "8S" | "16S" | "32F" => Some(("F", format!("F;{i}"))),
                _ => None,
            };
        }
    };
    Some((r.0, r.1.to_string()))
}

fn leak16(i: &str) -> &'static str {
    match i {
        "16L" => "I;16L",
        "16B" => "I;16B",
        _ => "I;16",
    }
}

/// Python's `number`: int(s), else float(s), else ValueError.
fn number(s: &str) -> Result<f64, Raise> {
    if let Some(i) = py_int(s.as_bytes()) {
        return Ok(i as f64);
    }
    py_float(s.as_bytes()).ok_or_else(|| Raise::value("could not convert string to float"))
}

enum SizeVal {
    Default,
    Scalar,
    Tuple(Vec<f64>),
}

pub(crate) fn open(data: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(data);
    if !f.read(100).contains(&b'\n') {
        return Err(Raise::syntax("not an IM file"));
    }
    f.seek(0);
    let mut n = 0;
    let mut mode: String = "L".into();
    let mut rawmode: String = "L".into();
    let mut size = SizeVal::Default;
    let mut has_lut = false;
    let mut s: Vec<u8>;
    loop {
        s = f.read(1).to_vec();
        if s == b"\r" {
            continue;
        }
        if s.is_empty() || s == b"\0" || s == b"\x1a" {
            break;
        }
        s.extend_from_slice(f.readline());
        if s.len() > 100 {
            return Err(Raise::syntax("not an IM file"));
        }
        let mut line = s.clone();
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
        } else if line.ends_with(b"\n") {
            line.truncate(line.len() - 1);
        }
        // ^([A-Za-z][^:]*):[ \t]*(.*)[ \t]*$ ; "." does not match "\n"
        let colon = line.iter().position(|&c| c == b':');
        let ok = !line.is_empty() && line[0].is_ascii_alphabetic() && colon.is_some();
        let ok = ok && !line[colon.unwrap_or(0) + 1..].contains(&b'\n');
        if !ok {
            return Err(Raise::syntax("Syntax error in IM header"));
        }
        let c = colon.expect("colon");
        let k: String = line[..c].iter().map(|&b| b as char).collect();
        let mut v = &line[c + 1..];
        while let Some((&b, rest)) = v.split_first() {
            if b == b' ' || b == b'\t' {
                v = rest;
            } else {
                break;
            }
        }
        let v: String = v.iter().map(|&b| b as char).collect();
        if k == "File size (no of images)" || k == "Scale (x,y)" || k == "Image size (x*y)" {
            let parts: Vec<f64> = v
                .replace('*', ",")
                .split(',')
                .map(number)
                .collect::<Result<_, _>>()?;
            if k == "Image size (x*y)" {
                size = if parts.len() == 1 {
                    SizeVal::Scalar
                } else {
                    SizeVal::Tuple(parts)
                };
            }
        } else if k == "Image type" {
            if let Some((m, r)) = open_info(&v) {
                mode = m.into();
                rawmode = r;
            } else {
                mode = v.clone();
            }
        } else if k == "Lut" {
            has_lut = true;
        }
        if TAGS.contains(&k.as_str()) {
            n += 1;
        }
    }
    if n == 0 {
        return Err(Raise::syntax("Not an IM file"));
    }
    let size = match size {
        SizeVal::Default => (512.0, 512.0),
        SizeVal::Scalar => return Err(Raise::type_error("'int' object is not iterable")),
        SizeVal::Tuple(t) => {
            if t.len() < 2 {
                return Err(Raise::index_error());
            }
            (t[0], t[1])
        }
    };
    while !s.is_empty() && !s.starts_with(b"\x1a") {
        s = f.read(1).to_vec();
    }
    if s.is_empty() {
        return Err(Raise::syntax("File truncated"));
    }
    let mut palette = None;
    if has_lut {
        let p = f.read(768).to_vec();
        let mut grey = true;
        for i in 0..256 {
            let (a, b, c) = (
                *p.get(i).ok_or_else(Raise::index_error)?,
                *p.get(i + 256).ok_or_else(Raise::index_error)?,
                *p.get(i + 512).ok_or_else(Raise::index_error)?,
            );
            if !(a == b && b == c) {
                grey = false;
            }
        }
        if matches!(mode.as_str(), "L" | "LA" | "P" | "PA") && !grey {
            if mode == "L" || mode == "P" {
                mode = "P".into();
                rawmode = "P".into();
            } else {
                mode = "PA".into();
                rawmode = "PA;L".into();
            }
            palette = Some(p);
        }
    }
    let offs = f.tell();
    // ImageFile.__init__ checks: min(size) <= 0
    if size.0.min(size.1) <= 0.0 || mode.is_empty() {
        return Err(Raise::syntax("not identified by this driver"));
    }
    let isize = (size.0 as i64, size.1 as i64);
    if size.0.fract() != 0.0 || size.1.fract() != 0.0 {
        // a float size opens, but nothing can load it
        let mut o = Opened::new(
            "IM",
            mode,
            isize,
            Box::new(NoDecoder("IM image with a float size")),
        );
        o.size = (size.0.ceil() as i64, size.1.ceil() as i64);
        return Ok(o);
    }
    let m = mode.clone();
    Ok(Opened::new(
        "IM",
        m,
        isize,
        Box::new(ImLoad {
            data,
            mode,
            rawmode,
            size: isize,
            offs,
            palette,
        }),
    ))
}

struct ImLoad<'a> {
    data: &'a [u8],
    mode: String,
    rawmode: String,
    size: (i64, i64),
    offs: usize,
    palette: Option<Vec<u8>>,
}

impl Load for ImLoad<'_> {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        let mode =
            Mode::from_name(&self.mode).ok_or_else(|| Raise::value("unrecognized image mode"))?;
        let (w, h) = (self.size.0 as usize, self.size.1 as usize);
        let mut c = Canvas::new(mode, w, h)?;
        if let Some(p) = &self.palette {
            let mut pal = Palette::default();
            for i in 0..256 {
                pal.rgba[i] = [p[i], p[i + 256], p[i + 512], 255];
            }
            c.palette = Some(pal);
        }
        if let Some(bits) = self
            .rawmode
            .strip_prefix("F;")
            .and_then(|b| b.parse::<u32>().ok())
        {
            if ![8, 16, 32].contains(&bits) {
                return Err(Raise::unsupported("IM bit decoder"));
            }
        }
        let find = |r: &str| {
            unpack::find(mode, r)
                .ok_or_else(|| Raise::value("unknown raw mode for given image mode"))
        };
        let mut tiles = Vec::new();
        if self.rawmode == "RGB;T" || self.rawmode == "RYB;T" {
            c.keep_native()?;
            let sz = w * h;
            for (i, b) in ["G", "R", "B"].iter().enumerate() {
                tiles.push(RawTile {
                    x0: 0,
                    y0: 0,
                    x1: w,
                    y1: h,
                    offset: self.offs + i * sz,
                    u: find(b)?,
                    stride: 0,
                    bottom_up: true,
                });
            }
        } else {
            tiles.push(RawTile {
                x0: 0,
                y0: 0,
                x1: w,
                y1: h,
                offset: self.offs,
                u: find(&self.rawmode)?,
                stride: 0,
                bottom_up: true,
            });
        }
        raw::load_tiles(&mut c, self.data, &mut tiles)?;
        Ok(c)
    }
}
