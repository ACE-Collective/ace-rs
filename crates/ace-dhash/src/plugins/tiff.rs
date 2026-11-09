//! TiffImagePlugin: the first IFD, read as Pillow reads it (`ImageFileDirectory_v2` and
//! `_setup`). Uncompressed images load through Pillow's raw tiles; compressed ones through
//! libtiff in Pillow, ported here for LZW, Deflate and PackBits with the horizontal
//! predictor. The image is then transposed by its Orientation tag, as Pillow's
//! `TiffImageFile.load_end` does with `ImageOps.exif_transpose`.
//!
//! Not decoded (Kind::Unsupported): JPEG, CCITT and the other compressions, YCbCr images
//! that libtiff reads as RGBA, the floating point predictor and old-style LZW codes.

use super::raw::{self, RawTile};
use crate::Raise;
use crate::image::{Canvas, Mode, Palette};
use crate::io::File;
use crate::open::{Load, Opened, bomb_check};
use crate::unpack::{self, Unpacker};
use std::collections::BTreeMap;

pub(crate) fn accept(prefix: &[u8]) -> Result<bool, Raise> {
    Ok([
        b"MM\x00\x2a",
        b"II\x2a\x00",
        b"MM\x2a\x00",
        b"II\x00\x2a",
        b"MM\x00\x2b",
        b"II\x2b\x00",
    ]
    .iter()
    .any(|p| prefix.starts_with(*p)))
}

/// A decoded tag value as Pillow returns it from `tag_v2[tag]`.
#[derive(Clone, Debug, PartialEq)]
enum Val {
    Int(i64),
    Float(f64),
    Rational(i64, i64),
    Bytes(Vec<u8>),
    Str,
    Tuple(Vec<Val>),
}

impl Val {
    fn int(&self) -> Option<i64> {
        match self {
            Val::Int(v) => Some(*v),
            _ => None,
        }
    }
    fn ints(&self) -> Option<Vec<i64>> {
        match self {
            Val::Tuple(v) => v.iter().map(|x| x.int()).collect(),
            Val::Int(v) => Some(vec![*v]),
            _ => None,
        }
    }
}

struct Ifd {
    big_endian: bool,
    bigtiff: bool,
    tagdata: BTreeMap<u16, (u16, Vec<u8>)>,
    offset: usize,
}

fn unit_size(typ: u16) -> Option<usize> {
    Some(match typ {
        1 | 2 | 6 | 7 => 1,
        3 | 8 => 2,
        4 | 9 | 11 | 13 => 4,
        5 | 10 | 12 | 16 => 8,
        _ => return None,
    })
}

/// TiffTags.lookup(tag).length for the tags read here: Some(1) single, Some(0) any, None
/// unknown.
fn tag_length(tag: u16) -> Option<usize> {
    match tag {
        254 | 256 | 257 | 259 | 262 | 266 | 274 | 277 | 278 | 282 | 283 | 284 | 296 | 317 | 322
        | 323 | 34675 => Some(1),
        258 | 273 | 279 | 320 | 324 | 325 | 338 | 339 | 700 => Some(0),
        530 => Some(2),
        532 => Some(6),
        _ => None,
    }
}

impl Ifd {
    fn u16(&self, b: &[u8]) -> u16 {
        if self.big_endian {
            u16::from_be_bytes([b[0], b[1]])
        } else {
            u16::from_le_bytes([b[0], b[1]])
        }
    }
    fn u32(&self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if self.big_endian {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    }
    fn u64(&self, b: &[u8]) -> u64 {
        let a: [u8; 8] = b[..8].try_into().expect("8 bytes");
        if self.big_endian {
            u64::from_be_bytes(a)
        } else {
            u64::from_le_bytes(a)
        }
    }

    /// ImageFileDirectory_v2.load: tags up to the first OSError are kept.
    fn load(&mut self, data: &[u8], at: usize) {
        self.tagdata.clear();
        self.offset = at;
        let mut f = File::new(data);
        f.seek(at);
        let limit = data.len() as u64;
        let mut total: u64 = 0;
        let count = if self.bigtiff {
            let b = f.read(8);
            if b.len() != 8 {
                return;
            }
            self.u64(b)
        } else {
            let b = f.read(2);
            if b.len() != 2 {
                return;
            }
            self.u16(b) as u64
        };
        for _ in 0..count {
            let entry = f.read(if self.bigtiff { 20 } else { 12 });
            if entry.len() != if self.bigtiff { 20 } else { 12 } {
                return;
            }
            let tag = self.u16(&entry[0..2]);
            let typ = self.u16(&entry[2..4]);
            let (cnt, raw) = if self.bigtiff {
                (self.u64(&entry[4..12]), &entry[12..20])
            } else {
                (self.u32(&entry[4..8]) as u64, &entry[8..12])
            };
            if self.tagdata.contains_key(&tag) {
                continue;
            }
            let Some(unit) = unit_size(typ) else {
                continue;
            };
            let size = cnt.saturating_mul(unit as u64);
            let inline = if self.bigtiff { 8 } else { 4 };
            let value: Vec<u8> = if size > inline {
                let off = if self.bigtiff {
                    self.u64(raw)
                } else {
                    self.u32(raw) as u64
                };
                if off >= 1 << 63 {
                    continue;
                }
                total += size;
                if total > limit {
                    continue;
                }
                let here = f.tell();
                let start = off as usize;
                let end = start.saturating_add(size as usize);
                if end > data.len() {
                    // _safe_read raises OSError, which ends the load
                    return;
                }
                let v = data[start..end].to_vec();
                f.seek(here);
                v
            } else {
                raw[..size as usize].to_vec()
            };
            if value.is_empty() {
                continue;
            }
            self.tagdata.insert(tag, (typ, value));
        }
    }

    /// `tag_v2[tag]`, or None for KeyError.
    fn get(&self, tag: u16) -> Option<Val> {
        let (typ, data) = self.tagdata.get(&tag)?;
        let be = self.big_endian;
        let mut vals: Vec<Val> = match typ {
            1 | 7 => vec![Val::Bytes(data.clone())],
            2 => vec![Val::Str],
            3 | 8 | 4 | 9 | 13 | 16 | 6 => {
                let u = unit_size(*typ).expect("unit");
                data.chunks_exact(u)
                    .map(|c| {
                        let mut b = [0u8; 8];
                        for (i, v) in c.iter().enumerate() {
                            b[if be { u - 1 - i } else { i }] = *v;
                        }
                        let raw = u64::from_le_bytes(b);
                        let signed = matches!(typ, 6 | 8 | 9);
                        let v = if signed {
                            let sh = 64 - 8 * u as u32;
                            ((raw << sh) as i64) >> sh
                        } else {
                            raw as i64
                        };
                        Val::Int(v)
                    })
                    .collect()
            }
            11 | 12 => {
                let u = unit_size(*typ).expect("unit");
                data.chunks_exact(u)
                    .map(|c| {
                        let mut b = [0u8; 8];
                        for (i, v) in c.iter().enumerate() {
                            b[if be { u - 1 - i } else { i }] = *v;
                        }
                        let v = if u == 4 {
                            f32::from_bits(u32::from_le_bytes([b[0], b[1], b[2], b[3]])) as f64
                        } else {
                            f64::from_bits(u64::from_le_bytes(b))
                        };
                        Val::Float(v)
                    })
                    .collect()
            }
            5 | 10 => {
                let n = data.len() / 4;
                let w: Vec<i64> = (0..n)
                    .map(|i| {
                        let c = &data[i * 4..i * 4 + 4];
                        let raw = self.u32(c);
                        if *typ == 10 {
                            raw as i32 as i64
                        } else {
                            raw as i64
                        }
                    })
                    .collect();
                w.chunks_exact(2)
                    .map(|p| Val::Rational(p[0], p[1]))
                    .collect()
            }
            _ => return None,
        };
        let single = tag_length(tag) == Some(1)
            || *typ == 1
            || (tag_length(tag).is_none() && vals.len() == 1);
        if single {
            if vals.len() != 1 {
                if tag == 262 {
                    return None;
                }
                return vals.drain(..).next();
            }
            return vals.pop();
        }
        Some(Val::Tuple(vals))
    }
}

/// OPEN_INFO.
fn open_info(
    mm: bool,
    photo: i64,
    sf: &[i64],
    fill: i64,
    bps: &[i64],
    extra: &[i64],
) -> Option<(&'static str, &'static str)> {
    let s1 = sf == [1];
    let r = match (photo, fill, bps, extra) {
        (0, 1, [1], []) if s1 => ("1", "1;I"),
        (0, 2, [1], []) if s1 => ("1", "1;IR"),
        (1, 1, [1], []) if s1 => ("1", "1"),
        (1, 2, [1], []) if s1 => ("1", "1;R"),
        (0, 1, [2], []) if s1 => ("L", "L;2I"),
        (0, 2, [2], []) if s1 => ("L", "L;2IR"),
        (1, 1, [2], []) if s1 => ("L", "L;2"),
        (1, 2, [2], []) if s1 => ("L", "L;2R"),
        (0, 1, [4], []) if s1 => ("L", "L;4I"),
        (0, 2, [4], []) if s1 => ("L", "L;4IR"),
        (1, 1, [4], []) if s1 => ("L", "L;4"),
        (1, 2, [4], []) if s1 => ("L", "L;4R"),
        (0, 1, [8], []) if s1 => ("L", "L;I"),
        (0, 2, [8], []) if s1 => ("L", "L;IR"),
        (1, 1, [8], []) if s1 || sf == [2] => ("L", "L"),
        (1, 2, [8], []) if s1 => ("L", "L;R"),
        (1, 1, [12], []) if s1 && !mm => ("I;16", "I;12"),
        (0, 1, [16], []) if s1 && !mm => ("I;16", "I;16"),
        (1, 1, [16], []) if s1 => {
            if mm {
                ("I;16B", "I;16B")
            } else {
                ("I;16", "I;16")
            }
        }
        (1, 2, [16], []) if s1 && !mm => ("I;16", "I;16R"),
        (1, 1, [16], []) if sf == [2] => {
            if mm {
                ("I", "I;16BS")
            } else {
                ("I", "I;16S")
            }
        }
        (0, 1, [32], []) if sf == [3] => {
            if mm {
                ("F", "F;32BF")
            } else {
                ("F", "F;32F")
            }
        }
        (1, 1, [32], []) if s1 && !mm => ("I", "I;32N"),
        (1, 1, [32], []) if sf == [2] => {
            if mm {
                ("I", "I;32BS")
            } else {
                ("I", "I;32S")
            }
        }
        (1, 1, [32], []) if sf == [3] => {
            if mm {
                ("F", "F;32BF")
            } else {
                ("F", "F;32F")
            }
        }
        (1, 1, [8, 8], [0]) if s1 => ("L", "LX"),
        (1, 1, [8, 8], [1]) if s1 => ("La", "La"),
        (1, 1, [8, 8], [2]) if s1 => ("LA", "LA"),
        (2, 1, [8, 8, 8], []) if s1 => ("RGB", "RGB"),
        (2, 2, [8, 8, 8], []) if s1 => ("RGB", "RGB;R"),
        (2, 1, [8, 8, 8, 8], []) if s1 => ("RGBA", "RGBA"),
        (2, 1, [8, 8, 8, 8], [0]) if s1 => ("RGB", "RGBX"),
        (2, 1, [8, 8, 8, 8, 8], [0, 0]) if s1 => ("RGB", "RGBXX"),
        (2, 1, [8, 8, 8, 8, 8, 8], [0, 0, 0]) if s1 => ("RGB", "RGBXXX"),
        (2, 1, [8, 8, 8, 8], [1]) if s1 => ("RGBA", "RGBa"),
        (2, 1, [8, 8, 8, 8, 8], [1, 0]) if s1 => ("RGBA", "RGBaX"),
        (2, 1, [8, 8, 8, 8, 8, 8], [1, 0, 0]) if s1 => ("RGBA", "RGBaXX"),
        (2, 1, [8, 8, 8, 8], [2]) if s1 => ("RGBA", "RGBA"),
        (2, 1, [8, 8, 8, 8, 8], [2, 0]) if s1 => ("RGBA", "RGBAX"),
        (2, 1, [8, 8, 8, 8, 8, 8], [2, 0, 0]) if s1 => ("RGBA", "RGBAXX"),
        (2, 1, [8, 8, 8, 8], [999]) if s1 => ("RGBA", "RGBA"),
        (2, 1, [16, 16, 16], []) if s1 => {
            if mm {
                ("RGB", "RGB;16B")
            } else {
                ("RGB", "RGB;16L")
            }
        }
        (2, 1, [16, 16, 16, 16], []) | (2, 1, [16, 16, 16, 16], [2]) if s1 => {
            if mm {
                ("RGBA", "RGBA;16B")
            } else {
                ("RGBA", "RGBA;16L")
            }
        }
        (2, 1, [16, 16, 16, 16], [0]) if s1 => {
            if mm {
                ("RGB", "RGBX;16B")
            } else {
                ("RGB", "RGBX;16L")
            }
        }
        (2, 1, [16, 16, 16, 16], [1]) if s1 => {
            if mm {
                ("RGBA", "RGBa;16B")
            } else {
                ("RGBA", "RGBa;16L")
            }
        }
        (3, 1, [1], []) if s1 => ("P", "P;1"),
        (3, 2, [1], []) if s1 => ("P", "P;1R"),
        (3, 1, [2], []) if s1 => ("P", "P;2"),
        (3, 2, [2], []) if s1 => ("P", "P;2R"),
        (3, 1, [4], []) if s1 => ("P", "P;4"),
        (3, 2, [4], []) if s1 => ("P", "P;4R"),
        (3, 1, [8], []) if s1 => ("P", "P"),
        (3, 1, [8, 8], [0]) if s1 => ("P", "PX"),
        (3, 1, [8, 8], [2]) if s1 => ("PA", "PA"),
        (3, 2, [8], []) if s1 => ("P", "P;R"),
        (5, 1, [8, 8, 8, 8], []) if s1 => ("CMYK", "CMYK"),
        (5, 1, [8, 8, 8, 8, 8], [0]) if s1 => ("CMYK", "CMYKX"),
        (5, 1, [8, 8, 8, 8, 8, 8], [0, 0]) if s1 => ("CMYK", "CMYKXX"),
        (5, 1, [16, 16, 16, 16], []) if s1 => {
            if mm {
                ("CMYK", "CMYK;16B")
            } else {
                ("CMYK", "CMYK;16L")
            }
        }
        (6, 1, [8], []) if s1 => ("L", "L"),
        (6, 1, [8, 8, 8], []) if s1 => ("YCbCr", "YCbCr"),
        (8, 1, [8, 8, 8], []) if s1 => ("LAB", "LAB"),
        _ => return None,
    };
    Some(r)
}

fn compression_name(c: &Val) -> Option<&'static str> {
    Some(match c.int()? {
        1 => "raw",
        2 => "tiff_ccitt",
        3 => "group3",
        4 => "group4",
        5 => "tiff_lzw",
        6 => "tiff_jpeg",
        7 => "jpeg",
        8 => "tiff_adobe_deflate",
        32771 => "tiff_raw_16",
        32773 => "packbits",
        32809 => "tiff_thunderscan",
        32946 => "tiff_deflate",
        34676 => "tiff_sgilog",
        34677 => "tiff_sgilog24",
        34925 => "lzma",
        50000 => "zstd",
        50001 => "webp",
        _ => return None,
    })
}

enum Plan {
    Raw(Vec<(usize, usize, usize, usize, usize, String, usize)>),
    Libtiff { rawmode: String },
}

pub(crate) fn open(data: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(data);
    let mut ifh = f.read(8).to_vec();
    if crate::io::byte(&ifh, 2)? == 43 {
        ifh.extend_from_slice(f.read(8));
    }
    if !accept(&ifh)? {
        return Err(Raise::syntax("not a TIFF file"));
    }
    let big_endian = &ifh[..2] == b"MM";
    let bigtiff = ifh[2] == 43;
    let mut ifd = Ifd {
        big_endian,
        bigtiff,
        tagdata: BTreeMap::new(),
        offset: 0,
    };
    let next = if bigtiff {
        let b = ifh.get(8..16).ok_or_else(Raise::struct_error)?;
        ifd.u64(b)
    } else {
        let b = ifh.get(4..8).ok_or_else(Raise::struct_error)?;
        ifd.u32(b) as u64
    };
    // _seek(0)
    if next == 0 {
        return Err(Raise::eof("no more images in TIFF file"));
    }
    if next >= 1 << 63 {
        return Err(Raise::value("Unable to seek to frame"));
    }
    ifd.load(data, next as usize);
    // _setup
    if ifd.tagdata.contains_key(&0xBC01) {
        return Err(Raise::os("Windows Media Photo files not yet supported"));
    }
    let comp = match ifd.get(259) {
        Some(v) => compression_name(&v).ok_or_else(Raise::key)?,
        None => "raw",
    };
    let planar = ifd.get(284).unwrap_or(Val::Int(1));
    let mut photo = ifd.get(262).unwrap_or(Val::Int(0));
    if comp == "tiff_jpeg" {
        photo = Val::Int(6);
    }
    let fillorder = ifd.get(266).unwrap_or(Val::Int(1));
    let (Some(xsize), Some(ysize)) = (ifd.get(256), ifd.get(257)) else {
        return Err(Raise::type_error("Missing dimensions"));
    };
    let (Some(xsize), Some(ysize)) = (xsize.int(), ysize.int()) else {
        return Err(Raise::value("Invalid dimensions"));
    };
    let orientation = ifd.get(274).and_then(|v| v.int());
    let size = if matches!(orientation, Some(5..=8)) {
        (ysize, xsize)
    } else {
        (xsize, ysize)
    };
    let photo = photo.int().ok_or_else(Raise::key)?;
    let planar = planar.int();
    let fillorder = fillorder.int().ok_or_else(Raise::key)?;
    let mut sf = ifd
        .get(339)
        .map_or(Some(vec![1]), |v| v.ints())
        .ok_or_else(Raise::key)?;
    if sf.len() > 1 && sf.iter().max() == sf.iter().min() {
        sf.truncate(1);
    }
    let mut bps = ifd
        .get(258)
        .map_or(Some(vec![1]), |v| v.ints())
        .ok_or_else(Raise::key)?;
    let mut extra = ifd
        .get(338)
        .map_or(Some(vec![]), |v| v.ints())
        .ok_or_else(Raise::key)?;
    let spp_default = if comp == "tiff_jpeg" && (photo == 2 || photo == 6) {
        3
    } else {
        1
    };
    let mut spp = match ifd.get(277) {
        Some(v) => v
            .int()
            .ok_or_else(|| Raise::type_error("bad samples per pixel"))?,
        None => spp_default,
    };
    let mut bps_count: i64 = match photo {
        2 | 6 | 8 => 3,
        5 => 4,
        _ => 1,
    };
    if planar == Some(2) && !extra.is_empty() && extra.iter().max() == Some(&0) {
        let n = extra.len();
        bps.truncate(bps.len().saturating_sub(n));
        spp -= n as i64;
        extra.clear();
    }
    bps_count += extra.len() as i64;
    if spp > 6 {
        return Err(Raise::syntax("Invalid value for samples per pixel"));
    }
    if spp < bps.len() as i64 {
        bps.truncate(spp.max(0) as usize);
    } else if spp > bps.len() as i64 && bps.len() == 1 {
        bps = vec![bps[0]; spp as usize];
    }
    if bps.len() as i64 != spp {
        return Err(Raise::syntax("unknown data organization"));
    }
    let (mut mode, mut rawmode) = open_info(big_endian, photo, &sf, fillorder, &bps, &extra)
        .ok_or_else(|| Raise::syntax("unknown pixel mode"))?;
    let use_libtiff = comp != "raw";
    let plan = if use_libtiff {
        if fillorder == 2 {
            let r = open_info(big_endian, photo, &sf, 1, &bps, &extra).ok_or_else(Raise::key)?;
            mode = r.0;
            rawmode = r.1;
        }
        let mut rm = rawmode.to_string();
        if photo == 6 {
            mode = "RGB";
            rm = if comp == "jpeg" && planar == Some(1) {
                "RGB".into()
            } else {
                "RGBX".into()
            };
        } else if rm == "I;16" {
            rm = "I;16N".into();
        } else if rm.ends_with(";16B") || rm.ends_with(";16L") {
            rm.pop();
            rm.push('N');
        }
        Plan::Libtiff { rawmode: rm }
    } else if ifd.tagdata.contains_key(&273) || ifd.tagdata.contains_key(&324) {
        let (offsets, w, h) = if ifd.tagdata.contains_key(&273) {
            let o = ifd
                .get(273)
                .and_then(|v| v.ints())
                .ok_or_else(|| Raise::type_error("bad offsets"))?;
            let h = match ifd.get(278) {
                Some(v) => v
                    .int()
                    .ok_or_else(|| Raise::type_error("bad rows per strip"))?,
                None => ysize,
            };
            (o, xsize, h)
        } else {
            let o = ifd
                .get(324)
                .and_then(|v| v.ints())
                .ok_or_else(|| Raise::type_error("bad offsets"))?;
            let tw = ifd.get(322).and_then(|v| v.int());
            let th = ifd.get(323).and_then(|v| v.int());
            let (Some(tw), Some(th)) = (tw, th) else {
                return Err(Raise::value("Invalid tile dimensions"));
            };
            (o, tw, th)
        };
        let offsets = if w == xsize && h == ysize && planar != Some(2) {
            offsets[offsets.len().saturating_sub(1)..].to_vec()
        } else {
            offsets
        };
        let mut tiles = Vec::new();
        let (mut x, mut y, mut layer) = (0i64, 0i64, 0usize);
        let sum_bps: i64 = bps.iter().sum();
        for off in offsets {
            let mut stride = if x + w > xsize {
                (w * sum_bps) as f64 / 8.0
            } else {
                0.0
            };
            let mut tile_rawmode = rawmode.to_string();
            if planar == Some(2) {
                tile_rawmode = rawmode
                    .chars()
                    .nth(layer)
                    .ok_or_else(Raise::index_error)?
                    .to_string();
                stride /= bps_count as f64;
            }
            let e = (x, y, (x + w).min(xsize), (y + h).min(ysize));
            tiles.push((
                e.0 as usize,
                e.1 as usize,
                e.2 as usize,
                e.3 as usize,
                off as usize,
                tile_rawmode,
                stride as usize,
            ));
            if e.0 < 0 || e.1 < 0 || e.2 < 0 || e.3 < 0 {
                tiles.pop();
                tiles.push((usize::MAX, 0, 0, 0, off.max(0) as usize, String::new(), 0));
            }
            x += w;
            if x >= xsize {
                x = 0;
                y += h;
                if y >= ysize {
                    y = 0;
                    layer += 1;
                }
            }
        }
        Plan::Raw(tiles)
    } else {
        return Err(Raise::syntax("unknown data organization"));
    };
    let mut palette = None;
    if mode == "P" || mode == "PA" {
        let cm = ifd.get(320).ok_or_else(Raise::key)?;
        let v = cm.ints().ok_or_else(|| Raise::type_error("bad colormap"))?;
        palette = Some(v.iter().map(|b| b.div_euclid(256)).collect::<Vec<i64>>());
    }
    Ok(Opened::new(
        "TIFF",
        mode,
        size,
        Box::new(TiffLoad {
            data,
            ifd,
            mode,
            tile_size: (xsize, ysize),
            plan,
            palette,
            comp,
            orientation,
        }),
    ))
}

struct TiffLoad<'a> {
    data: &'a [u8],
    ifd: Ifd,
    mode: &'static str,
    tile_size: (i64, i64),
    plan: Plan,
    palette: Option<Vec<i64>>,
    comp: &'static str,
    orientation: Option<i64>,
}

fn find(mode: Mode, raw: &str) -> Result<Unpacker, Raise> {
    unpack::find(mode, raw).ok_or_else(|| Raise::value("unknown raw mode for given image mode"))
}

impl Load for TiffLoad<'_> {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        bomb_check(self.tile_size)?;
        let mode = Mode::from_name(self.mode).ok_or_else(Raise::key)?;
        let (w, h) = (self.tile_size.0 as usize, self.tile_size.1 as usize);
        let mut c = Canvas::new(mode, w, h)?;
        if let Some(p) = &self.palette {
            // ImagePalette.raw("RGB;L", palette): bytes, then planar R, G, B
            if p.iter().any(|&v| !(0..256).contains(&v)) {
                return Err(Raise::value("bytes must be in range(0, 256)"));
            }
            let bytes: Vec<u8> = p.iter().map(|&v| v as u8).collect();
            let n = bytes.len() / 3;
            if n > 256 {
                return Err(Raise::value("invalid palette size"));
            }
            let mut pal = Palette::default();
            for i in 0..n {
                pal.rgba[i] = [bytes[i], bytes[i + n], bytes[i + 2 * n], 255];
            }
            c.palette = Some(pal);
        }
        match &self.plan {
            Plan::Raw(tiles) => {
                let mut sorted = tiles.clone();
                sorted.sort_by_key(|t| t.4);
                // itertools.groupby over consecutive equal (extents, args): keep the last
                let mut kept: Vec<(usize, usize, usize, usize, usize, String, usize)> = Vec::new();
                for t in sorted {
                    if let Some(last) = kept.last() {
                        if (last.0, last.1, last.2, last.3, &last.5, last.6)
                            == (t.0, t.1, t.2, t.3, &t.5, t.6)
                        {
                            kept.pop();
                        }
                    }
                    kept.push(t);
                }
                if kept.iter().any(|t| t.5 != kept[0].5)
                    || kept
                        .iter()
                        .any(|t| unpack::find(mode, &t.5).is_some_and(|u| u.partial))
                {
                    c.keep_native()?;
                }
                let mut rt = Vec::new();
                for t in &kept {
                    if t.0 == usize::MAX {
                        return Err(Raise::value("tile cannot extend outside image"));
                    }
                    rt.push(RawTile {
                        x0: t.0,
                        y0: t.1,
                        x1: t.2,
                        y1: t.3,
                        offset: t.4,
                        u: find(mode, &t.5)?,
                        stride: t.6,
                        bottom_up: false,
                    });
                }
                raw::load_tiles(&mut c, self.data, &mut rt)?;
            }
            Plan::Libtiff { rawmode } => {
                libtiff_decode(&self, &mut c, rawmode)?;
            }
        }
        // load_end: ImageOps.exif_transpose
        transpose(&mut c, self.orientation);
        Ok(c)
    }
}

fn transpose(c: &mut Canvas, orientation: Option<i64>) {
    let Some(o @ 2..=8) = orientation else {
        return;
    };
    let (w, h) = (c.w, c.h);
    let src = if let Some(n) = c.native.take() {
        // convert to gray first; transposing is per pixel
        let ps = c.mode.pixel_size();
        n.chunks_exact(ps)
            .map(|p| crate::image::pixel_to_l(c.mode, p))
            .collect()
    } else {
        std::mem::take(&mut c.px)
    };
    let (nw, nh) = if o >= 5 { (h, w) } else { (w, h) };
    let mut out = vec![0u8; w * h];
    for y in 0..h {
        for x in 0..w {
            let (nx, ny) = match o {
                2 => (w - 1 - x, y),
                3 => (w - 1 - x, h - 1 - y),
                4 => (x, h - 1 - y),
                5 => (y, x),
                6 => (h - 1 - y, x),
                7 => (h - 1 - y, w - 1 - x),
                _ => (y, w - 1 - x),
            };
            out[ny * nw + nx] = src[y * w + x];
        }
    }
    c.px = out;
    c.w = nw;
    c.h = nh;
}

/// Pillow's ImagingLibTiffDecode over libtiff's strip and tile reading.
fn libtiff_decode(t: &TiffLoad, c: &mut Canvas, rawmode: &str) -> Result<(), Raise> {
    let broken = || Raise::os("decoder error -2");
    let ifd = &t.ifd;
    let geti = |tag: u16| ifd.get(tag).and_then(|v| v.int());
    let photo = geti(262).unwrap_or(-1);
    let comp = geti(259).unwrap_or(1);
    let planar = geti(284).unwrap_or(1);
    if photo == 6 {
        return Err(Raise::unsupported("TIFF YCbCr read as RGBA by libtiff"));
    }
    let decode: fn(&[u8], &mut [u8]) -> Result<(), &'static str> = match t.comp {
        "tiff_lzw" => crate::lzw::tiff_lzw,
        "tiff_adobe_deflate" | "tiff_deflate" => crate::lzw::deflate,
        "packbits" => crate::lzw::packbits,
        other => {
            let _ = other;
            return Err(Raise::unsupported("TIFF compression"));
        }
    };
    let _ = comp;
    let mode = c.mode;
    let bands = match mode {
        Mode::One | Mode::L | Mode::P | Mode::I | Mode::F | Mode::I16 | Mode::I16B => 1,
        Mode::LA | Mode::PA | Mode::La => 2,
        Mode::Rgb | Mode::YCbCr | Mode::Lab | Mode::Hsv => 3,
        _ => 4,
    };
    let state_u = find(mode, rawmode)?;
    let spp = geti(277).unwrap_or(1).max(1) as usize;
    let bps_v = ifd.get(258).and_then(|v| v.ints()).unwrap_or(vec![1]);
    let bps = bps_v[0].max(1) as usize;
    let (planes, unpackers): (usize, Vec<Unpacker>) = if planar == 2 && bands > 1 {
        if bps != 8 && bps != 16 {
            return Err(broken());
        }
        let names: [&str; 4] = if bps == 16 {
            ["R;16N", "G;16N", "B;16N", "A;16N"]
        } else {
            ["R", "G", "B", "A"]
        };
        c.keep_native()?;
        let u = names
            .iter()
            .map(|n| find(Mode::Rgba, n))
            .collect::<Result<Vec<_>, _>>()?;
        (bands, u)
    } else {
        (1, vec![state_u])
    };
    let (w, h) = (c.w, c.h);
    let predictor = geti(317).unwrap_or(1);
    if predictor == 3 {
        return Err(Raise::unsupported("TIFF floating point predictor"));
    }
    if predictor == 2 && ![8, 16, 32, 64].contains(&bps) {
        return Err(broken());
    }
    let swab = t.ifd.big_endian && bps > 8;
    let fill_rev = geti(266) == Some(2);
    let pred_stride = if planar == 1 { spp } else { 1 };
    let samples_per_row = if planar == 1 { spp } else { 1 };
    let bits = state_u.bits;
    let decode_chunk = |raw: &[u8], out: &mut [u8], row_bytes: usize| -> Result<(), Raise> {
        let mut src = raw.to_vec();
        if fill_rev {
            for b in &mut src {
                *b = b.reverse_bits();
            }
        }
        decode(&src, out).map_err(|_| broken())?;
        if predictor == 2 && out.len() % row_bytes != 0 {
            return Err(broken());
        }
        if swab {
            match bps {
                16 => out.chunks_exact_mut(2).for_each(|c| c.swap(0, 1)),
                32 => out.chunks_exact_mut(4).for_each(|c| c.reverse()),
                64 => out.chunks_exact_mut(8).for_each(|c| c.reverse()),
                _ => {}
            }
        }
        if predictor == 2 {
            for row in out.chunks_exact_mut(row_bytes) {
                hor_acc(row, bps, pred_stride);
            }
        }
        Ok(())
    };
    let tiled = ifd.tagdata.contains_key(&322);
    let file_len = t.data.len() as u64;
    let read_strip = |offsets: &[i64], counts: &[i64], i: usize| -> Result<&[u8], Raise> {
        let off = *offsets.get(i).ok_or_else(broken)? as u64;
        let cnt = *counts.get(i).ok_or_else(broken)? as u64;
        if cnt == 0 || cnt > file_len || off > file_len - cnt {
            return Err(broken());
        }
        Ok(&t.data[off as usize..(off + cnt) as usize])
    };
    let byte_counts = |tag: u16, offsets: &[i64]| -> Vec<i64> {
        match ifd.get(tag).and_then(|v| v.ints()) {
            Some(v) if !(v.len() == 1 && v[0] == 0) => v,
            _ => offsets
                .iter()
                .map(|&o| (file_len as i64 - o).max(0))
                .collect(),
        }
    };
    if !tiled {
        let offsets = ifd.get(273).and_then(|v| v.ints()).ok_or_else(broken)?;
        let counts = byte_counts(279, &offsets);
        let mut rps = geti(278).unwrap_or(u32::MAX as i64) as u64;
        if rps == u32::MAX as u64 || rps == 0 {
            rps = h as u64;
        }
        let rps = rps.min(h as u64).max(1) as usize;
        let scan = (w * samples_per_row * bps).div_ceil(8);
        let strip_size = rps * scan;
        let unpack_row = (w * bits / planes).div_ceil(8);
        if strip_size > unpack_row * rps || scan == 0 || unpack_row > scan {
            return Err(broken());
        }
        let strips_per_image = h.div_ceil(rps);
        let mut buf = vec![0u8; strip_size];
        let mut y = 0;
        while y < h {
            for plane in 0..planes {
                let strip = y / rps + plane * strips_per_image;
                let rows = rps.min(h - y);
                let raw = read_strip(&offsets, &counts, strip)?;
                decode_chunk(raw, &mut buf[..rows * scan], scan)?;
                for r in 0..rows {
                    c.unpack_row(&unpackers[plane], 0, y + r, &buf[r * scan..], w);
                }
            }
            y += rps;
        }
    } else {
        let offsets = ifd.get(324).and_then(|v| v.ints()).ok_or_else(broken)?;
        let counts = byte_counts(325, &offsets);
        let tw = geti(322).unwrap_or(0).max(0) as usize;
        let th = geti(323).unwrap_or(0).max(0) as usize;
        if tw == 0 || th == 0 {
            return Err(broken());
        }
        let row = (tw * samples_per_row * bps).div_ceil(8);
        let tile_bytes = row * th;
        let unpack_row = (tw * bits / planes).div_ceil(8);
        if tile_bytes != unpack_row * th || unpack_row > row {
            return Err(broken());
        }
        let across = w.div_ceil(tw);
        let down = h.div_ceil(th);
        let mut buf = vec![0u8; tile_bytes];
        let mut y = 0;
        while y < h {
            for plane in 0..planes {
                let mut x = 0;
                while x < w {
                    let tile = (y / th) * across + x / tw + plane * across * down;
                    let raw = read_strip(&offsets, &counts, tile)?;
                    decode_chunk(raw, &mut buf, row)?;
                    let cw = tw.min(w - x);
                    let ch = th.min(h - y);
                    for r in 0..ch {
                        c.unpack_row(&unpackers[plane], x, y + r, &buf[r * row..], cw);
                    }
                    x += tw;
                }
            }
            y += th;
        }
    }
    if planes > 3 && mode == Mode::Rgba {
        let extra = ifd.get(338).and_then(|v| v.ints()).unwrap_or_default();
        if extra.first().is_some_and(|&e| e == 0 || e == 1) {
            let u = find(Mode::Rgba, "RGBa")?;
            if let Some(n) = &mut c.native {
                let copy = n.clone();
                u.run(n, &copy, w * h);
            }
        }
    }
    Ok(())
}

/// libtiff's horAcc8/16/32/64 over one row (samples already in host order).
fn hor_acc(row: &mut [u8], bps: usize, stride: usize) {
    match bps {
        8 => {
            for i in stride..row.len() {
                row[i] = row[i].wrapping_add(row[i - stride]);
            }
        }
        16 => {
            let n = row.len() / 2;
            for i in stride..n {
                let a = u16::from_le_bytes([row[2 * i], row[2 * i + 1]]);
                let b = u16::from_le_bytes([row[2 * (i - stride)], row[2 * (i - stride) + 1]]);
                row[2 * i..2 * i + 2].copy_from_slice(&a.wrapping_add(b).to_le_bytes());
            }
        }
        32 => {
            let n = row.len() / 4;
            for i in stride..n {
                let a = u32::from_le_bytes(row[4 * i..4 * i + 4].try_into().expect("4"));
                let b = u32::from_le_bytes(
                    row[4 * (i - stride)..4 * (i - stride) + 4]
                        .try_into()
                        .expect("4"),
                );
                row[4 * i..4 * i + 4].copy_from_slice(&a.wrapping_add(b).to_le_bytes());
            }
        }
        _ => {
            let n = row.len() / 8;
            for i in stride..n {
                let a = u64::from_le_bytes(row[8 * i..8 * i + 8].try_into().expect("8"));
                let b = u64::from_le_bytes(
                    row[8 * (i - stride)..8 * (i - stride) + 8]
                        .try_into()
                        .expect("8"),
                );
                row[8 * i..8 * i + 8].copy_from_slice(&a.wrapping_add(b).to_le_bytes());
            }
        }
    }
}
