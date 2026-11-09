//! Pillow's raw unpackers (`Unpack.c`): from a file's raw mode to an image mode's memory layout.
//!
//! Only the (mode, rawmode) pairs some decoder here uses are listed; any other pair is
//! Pillow's ValueError "unknown raw mode for given image mode", which is what a missing pair
//! gives too.

use crate::image::Mode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum U {
    Bits1 {
        invert: bool,
        lsb: bool,
    },
    Bool8,
    Gray2 {
        invert: bool,
        rev: bool,
    },
    Gray4 {
        invert: bool,
        rev: bool,
    },
    Copy1,
    Invert1,
    Flip1,
    /// One byte of a 16-bit sample: the byte at this offset.
    Byte16(usize),
    Idx1,
    Idx2,
    Idx4,
    /// "P;2L" and "P;4L": bit planes of a row, one after the other.
    IdxPlanes(usize),
    /// "BGRA;15Z": 5/5/5 with an inverted alpha bit.
    Bgra15Z,
    La,
    LaPlanar,
    /// 8-bit channels: `src[i]` gives the input byte of output channel i (None is 255), with
    /// `step` input bytes a pixel.
    Map {
        step: usize,
        src: [Option<u8>; 4],
        invert: [bool; 4],
    },
    /// One band of a planar image, into channel `ch`.
    Band {
        ch: usize,
        step: usize,
        off: usize,
        invert: bool,
    },
    Planar4,
    Rgb15 {
        bgr: bool,
        alpha: bool,
    },
    Rgb16 {
        bgr: bool,
    },
    Rgb4B {
        alpha: bool,
    },
    Premul {
        step: usize,
        src: [u8; 4],
    },
    Cmyk2Rgb,
    /// An integer or float sample into mode "I" (i32) or "F" (f32).
    Num {
        bytes: usize,
        big: bool,
        signed: bool,
        float_in: bool,
        float_out: bool,
    },
    /// 16-bit samples into "I;16" (little endian) or "I;16B" (big endian).
    I16 {
        swap: bool,
        flip: bool,
    },
    I12,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Unpacker {
    pub(crate) bits: usize,
    pub(crate) u: U,
    /// Writes only some channels of each pixel (a band of a planar image).
    pub(crate) partial: bool,
}

const fn m(step: usize, s: [i8; 4]) -> U {
    let mut src = [None; 4];
    let mut i = 0;
    while i < 4 {
        if s[i] >= 0 {
            src[i] = Some(s[i] as u8);
        }
        i += 1;
    }
    U::Map {
        step,
        src,
        invert: [false; 4],
    }
}

fn num(bytes: usize, big: bool, signed: bool, float_in: bool, float_out: bool) -> U {
    U::Num {
        bytes,
        big,
        signed,
        float_in,
        float_out,
    }
}

pub(crate) fn find(mode: Mode, raw: &str) -> Option<Unpacker> {
    use Mode as M;
    let (bits, u) = match (mode, raw) {
        (M::One, "1") => (
            1,
            U::Bits1 {
                invert: false,
                lsb: false,
            },
        ),
        (M::One, "1;I") => (
            1,
            U::Bits1 {
                invert: true,
                lsb: false,
            },
        ),
        (M::One, "1;R") => (
            1,
            U::Bits1 {
                invert: false,
                lsb: true,
            },
        ),
        (M::One, "1;IR") => (
            1,
            U::Bits1 {
                invert: true,
                lsb: true,
            },
        ),
        (M::One, "1;8") | (M::One, "L") => (8, U::Bool8),
        (M::L, "L;2") => (
            2,
            U::Gray2 {
                invert: false,
                rev: false,
            },
        ),
        (M::L, "L;2I") => (
            2,
            U::Gray2 {
                invert: true,
                rev: false,
            },
        ),
        (M::L, "L;2R") => (
            2,
            U::Gray2 {
                invert: false,
                rev: true,
            },
        ),
        (M::L, "L;2IR") => (
            2,
            U::Gray2 {
                invert: true,
                rev: true,
            },
        ),
        (M::L, "L;4") => (
            4,
            U::Gray4 {
                invert: false,
                rev: false,
            },
        ),
        (M::L, "L;4I") => (
            4,
            U::Gray4 {
                invert: true,
                rev: false,
            },
        ),
        (M::L, "L;4R") => (
            4,
            U::Gray4 {
                invert: false,
                rev: true,
            },
        ),
        (M::L, "L;4IR") => (
            4,
            U::Gray4 {
                invert: true,
                rev: true,
            },
        ),
        (M::L, "L") | (M::P, "P") | (M::P, "L") => (8, U::Copy1),
        (M::L, "L;I") => (8, U::Invert1),
        (M::L, "L;R") | (M::P, "P;R") => (8, U::Flip1),
        (M::L, "L;16") => (16, U::Byte16(1)),
        (M::L, "L;16B") | (M::L, "LX") | (M::P, "PX") => (16, U::Byte16(0)),
        (M::LA, "LA") | (M::La, "La") | (M::PA, "PA") | (M::PA, "LA") => (16, U::La),
        (M::LA, "LA;L") | (M::PA, "PA;L") => (16, U::LaPlanar),
        (M::P, "P;1") => (1, U::Idx1),
        (M::P, "P;2") => (2, U::Idx2),
        (M::P, "P;4") => (4, U::Idx4),
        (M::P, "P;2L") => (2, U::IdxPlanes(2)),
        (M::P, "P;4L") => (4, U::IdxPlanes(4)),
        (M::Rgba, "BGRA;15Z") => (16, U::Bgra15Z),
        (M::Rgb | M::Rgbx, "RGB") | (M::YCbCr, "YCbCr") | (M::Hsv, "HSV") => {
            (24, m(3, [0, 1, 2, -1]))
        }
        (M::Rgb | M::Rgbx, "RGB;L") | (M::YCbCr, "YCbCr;L") => (24, U::Planar4),
        (M::Rgb | M::Rgbx, "RGB;16L") => (48, m(6, [1, 3, 5, -1])),
        (M::Rgb | M::Rgbx, "RGB;16B" | "RGB;16N") => (48, m(6, [0, 2, 4, -1])),
        (M::Rgb | M::Rgbx | M::Rgba, "BGR") => (24, m(3, [2, 1, 0, -1])),
        (M::Rgb | M::Rgbx, "RGB;15") => (
            16,
            U::Rgb15 {
                bgr: false,
                alpha: false,
            },
        ),
        (M::Rgb | M::Rgbx, "BGR;15" | "BGR;5") => (
            16,
            U::Rgb15 {
                bgr: true,
                alpha: false,
            },
        ),
        (M::Rgb, "RGB;16") => (16, U::Rgb16 { bgr: false }),
        (M::Rgb, "BGR;16") => (16, U::Rgb16 { bgr: true }),
        (M::Rgb | M::Rgbx, "RGBX;16L") => (64, m(8, [1, 3, 5, 7])),
        (M::Rgb | M::Rgbx, "RGBX;16B" | "RGBX;16N") => (64, m(8, [0, 2, 4, 6])),
        (M::Rgb | M::Rgbx, "RGB;4B") => (16, U::Rgb4B { alpha: false }),
        (M::Rgb | M::Rgbx, "RGBX") | (M::Cmyk, "CMYK") | (M::YCbCr, "YCbCrX" | "YCbCrK") => {
            (32, m(4, [0, 1, 2, 3]))
        }
        (M::Rgb | M::Rgbx | M::Rgba, "RGBX;L" | "RGBA;L") | (M::Cmyk, "CMYK;L") => (32, U::Planar4),
        (M::Rgb | M::Rgbx, "RGBXX") => (40, m(5, [0, 1, 2, 3])),
        (M::Rgb | M::Rgbx, "RGBXXX") => (48, m(6, [0, 1, 2, 3])),
        (M::Rgb, "RGBA;15") => (
            16,
            U::Rgb15 {
                bgr: false,
                alpha: true,
            },
        ),
        (M::Rgb | M::Rgbx, "BGRX") => (32, m(4, [2, 1, 0, -1])),
        (M::Rgb, "BGXR") => (32, m(4, [3, 1, 0, -1])),
        (M::Rgb | M::Rgbx, "XRGB") => (32, m(4, [1, 2, 3, -1])),
        (M::Rgb | M::Rgbx, "XBGR") => (32, m(4, [3, 2, 1, -1])),
        (M::Rgb, "CMYK") => (32, U::Cmyk2Rgb),
        (M::Rgba, "LA") => (16, m(2, [0, 0, 0, 1])),
        (M::Rgba, "LA;16B") => (32, m(4, [0, 0, 0, 2])),
        (M::Rgba, "RGBA") | (M::RgbaPre, "RGBa") => (32, m(4, [0, 1, 2, 3])),
        (M::Rgba, "RGBAX") | (M::Cmyk, "CMYKX") => (40, m(5, [0, 1, 2, 3])),
        (M::Rgba, "RGBAXX") | (M::Cmyk, "CMYKXX") => (48, m(6, [0, 1, 2, 3])),
        (M::Rgba, "RGBa") => (
            32,
            U::Premul {
                step: 4,
                src: [0, 1, 2, 3],
            },
        ),
        (M::Rgba, "RGBaX") => (
            40,
            U::Premul {
                step: 5,
                src: [0, 1, 2, 3],
            },
        ),
        (M::Rgba, "RGBaXX") => (
            48,
            U::Premul {
                step: 6,
                src: [0, 1, 2, 3],
            },
        ),
        (M::Rgba, "RGBa;16L") => (
            64,
            U::Premul {
                step: 8,
                src: [1, 3, 5, 7],
            },
        ),
        (M::Rgba, "RGBa;16B" | "RGBa;16N") => (
            64,
            U::Premul {
                step: 8,
                src: [0, 2, 4, 6],
            },
        ),
        (M::Rgba, "BGRa") => (
            32,
            U::Premul {
                step: 4,
                src: [2, 1, 0, 3],
            },
        ),
        (M::Rgba, "RGBA;I") => (
            32,
            U::Map {
                step: 4,
                src: [Some(0), Some(1), Some(2), Some(3)],
                invert: [true, true, true, false],
            },
        ),
        (M::Rgba, "RGBA;15") => (
            16,
            U::Rgb15 {
                bgr: false,
                alpha: true,
            },
        ),
        (M::Rgba, "BGRA;15") => (
            16,
            U::Rgb15 {
                bgr: true,
                alpha: true,
            },
        ),
        (M::Rgba, "RGBA;4B") => (16, U::Rgb4B { alpha: true }),
        (M::Rgba, "RGBA;16L") | (M::Cmyk, "CMYK;16L") => (64, m(8, [1, 3, 5, 7])),
        (M::Rgba, "RGBA;16B" | "RGBA;16N") | (M::Cmyk, "CMYK;16B" | "CMYK;16N") => {
            (64, m(8, [0, 2, 4, 6]))
        }
        (M::Rgba, "BGRA") | (M::RgbaPre, "BGRa") => (32, m(4, [2, 1, 0, 3])),
        (M::Rgba, "BGRA;16L") => (64, m(8, [5, 3, 1, 7])),
        (M::Rgba, "BGRA;16B") => (64, m(8, [4, 2, 0, 6])),
        (M::Rgba, "BGAR") => (32, m(4, [3, 1, 0, 2])),
        (M::Rgba, "ARGB") | (M::RgbaPre, "aRGB") => (32, m(4, [1, 2, 3, 0])),
        (M::Rgba, "ABGR") | (M::RgbaPre, "aBGR") => (32, m(4, [3, 2, 1, 0])),
        (M::Cmyk, "CMYK;I") => (
            32,
            U::Map {
                step: 4,
                src: [Some(0), Some(1), Some(2), Some(3)],
                invert: [true; 4],
            },
        ),
        (M::Rgb | M::Rgba | M::Rgbx | M::Cmyk | M::Lab | M::Hsv, b) if band(b).is_some() => {
            let (ch, step, off, invert) = band(b)?;
            (
                step * 8,
                U::Band {
                    ch,
                    step,
                    off,
                    invert,
                },
            )
        }
        (M::Lab, "LAB") => (24, m(3, [0, 1, 2, -1])),
        (M::I, "I" | "I;32NS" | "I;32S") => (32, num(4, false, true, false, false)),
        (M::I, "I;8") => (8, num(1, false, false, false, false)),
        (M::I, "I;8S") => (8, num(1, false, true, false, false)),
        (M::I, "I;16" | "I;16N") => (16, num(2, false, false, false, false)),
        (M::I, "I;16S" | "I;16NS") => (16, num(2, false, true, false, false)),
        (M::I, "I;16B") => (16, num(2, true, false, false, false)),
        (M::I, "I;16BS") => (16, num(2, true, true, false, false)),
        (M::I, "I;32" | "I;32N") => (32, num(4, false, false, false, false)),
        (M::I, "I;32B") => (32, num(4, true, false, false, false)),
        (M::I, "I;32BS") => (32, num(4, true, true, false, false)),
        (M::F, "F" | "F;32F" | "F;32NF") => (32, num(4, false, false, true, true)),
        (M::F, "F;8") => (8, num(1, false, false, false, true)),
        (M::F, "F;8S") => (8, num(1, false, true, false, true)),
        (M::F, "F;16" | "F;16N") => (16, num(2, false, false, false, true)),
        (M::F, "F;16S" | "F;16NS") => (16, num(2, false, true, false, true)),
        (M::F, "F;16B") => (16, num(2, true, false, false, true)),
        (M::F, "F;16BS") => (16, num(2, true, true, false, true)),
        (M::F, "F;32" | "F;32N") => (32, num(4, false, false, false, true)),
        (M::F, "F;32S" | "F;32NS") => (32, num(4, false, true, false, true)),
        (M::F, "F;32B") => (32, num(4, true, false, false, true)),
        (M::F, "F;32BS") => (32, num(4, true, true, false, true)),
        (M::F, "F;32BF") => (32, num(4, true, false, true, true)),
        (M::F, "F;64F" | "F;64NF") => (64, num(8, false, false, true, true)),
        (M::F, "F;64BF") => (64, num(8, true, false, true, true)),
        (M::I16, "I;16" | "I;16L" | "I;16N") => (
            16,
            U::I16 {
                swap: false,
                flip: false,
            },
        ),
        (M::I16B, "I;16B") => (
            16,
            U::I16 {
                swap: false,
                flip: false,
            },
        ),
        (M::I16, "I;16B") | (M::I16B, "I;16N") => (
            16,
            U::I16 {
                swap: true,
                flip: false,
            },
        ),
        (M::I16, "I;16R") => (
            16,
            U::I16 {
                swap: false,
                flip: true,
            },
        ),
        (M::I16, "I;12") => (12, U::I12),
        _ => return None,
    };
    let partial = matches!(u, U::Band { .. });
    Some(Unpacker { bits, u, partial })
}

/// The band rawmodes: "R", "G;16L", "C;I" and the like.
fn band(b: &str) -> Option<(usize, usize, usize, bool)> {
    let (name, suffix) = match b.split_once(';') {
        Some((n, s)) => (n, s),
        None => (b, ""),
    };
    let ch = match name {
        "R" | "C" | "L" => 0,
        "G" | "M" => 1,
        "B" | "Y" => 2,
        "A" | "K" | "X" => 3,
        _ => return None,
    };
    let (step, off, invert) = match suffix {
        "" => (1, 0, false),
        "I" => (1, 0, true),
        "16L" => (2, 1, false),
        "16B" | "16N" => (2, 0, false),
        _ => return None,
    };
    Some((ch, step, off, invert))
}

const fn bitflip_table() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = (i as u8).reverse_bits();
        i += 1;
    }
    t
}
const BITFLIP: [u8; 256] = bitflip_table();

impl Unpacker {
    /// Bytes of input for `pixels` pixels.
    pub(crate) fn row_bytes(&self, pixels: usize) -> usize {
        if let U::IdxPlanes(p) = self.u {
            return p * pixels.div_ceil(8);
        }
        (pixels * self.bits).div_ceil(8)
    }

    /// `state->shuffle(out, in, pixels)`. `out` holds `pixels` pixels of the mode's layout.
    pub(crate) fn run(&self, out: &mut [u8], input: &[u8], pixels: usize) {
        match self.u {
            U::Bits1 { invert, lsb } => {
                for i in 0..pixels {
                    let byte = input[i / 8];
                    let bit = if lsb {
                        (byte >> (i % 8)) & 1
                    } else {
                        (byte >> (7 - i % 8)) & 1
                    };
                    out[i] = if (bit != 0) != invert { 255 } else { 0 };
                }
            }
            U::Bool8 => {
                for i in 0..pixels {
                    out[i] = if input[i] > 0 { 255 } else { 0 };
                }
            }
            U::Gray2 { invert, rev } => {
                for i in 0..pixels {
                    let mut byte = input[i / 4];
                    if rev {
                        byte = BITFLIP[byte as usize];
                    }
                    let v = ((byte >> (6 - 2 * (i % 4))) & 3) * 0x55;
                    out[i] = if invert { !v } else { v };
                }
            }
            U::Gray4 { invert, rev } => {
                for i in 0..pixels {
                    let mut byte = input[i / 2];
                    if rev {
                        byte = BITFLIP[byte as usize];
                    }
                    let v = ((byte >> (4 - 4 * (i % 2))) & 15) * 0x11;
                    out[i] = if invert { !v } else { v };
                }
            }
            U::Copy1 => out[..pixels].copy_from_slice(&input[..pixels]),
            U::Invert1 => {
                for i in 0..pixels {
                    out[i] = !input[i];
                }
            }
            U::Flip1 => {
                for i in 0..pixels {
                    out[i] = BITFLIP[input[i] as usize];
                }
            }
            U::Byte16(off) => {
                for i in 0..pixels {
                    out[i] = input[i * 2 + off];
                }
            }
            U::Idx1 => {
                for i in 0..pixels {
                    out[i] = (input[i / 8] >> (7 - i % 8)) & 1;
                }
            }
            U::Idx2 => {
                for i in 0..pixels {
                    out[i] = (input[i / 4] >> (6 - 2 * (i % 4))) & 3;
                }
            }
            U::Idx4 => {
                for i in 0..pixels {
                    out[i] = (input[i / 2] >> (4 - 4 * (i % 2))) & 15;
                }
            }
            U::IdxPlanes(planes) => {
                let s = pixels.div_ceil(8);
                for i in 0..pixels {
                    let (j, m) = (i / 8, 0x80u8 >> (i % 8));
                    let mut v = 0u8;
                    for p in 0..planes {
                        if input[j + p * s] & m != 0 {
                            v |= 1 << p;
                        }
                    }
                    out[i] = v;
                }
            }
            U::Bgra15Z => {
                for i in 0..pixels {
                    let p = input[i * 2] as u32 | (input[i * 2 + 1] as u32) << 8;
                    let b = (p & 31) * 255 / 31;
                    let g = ((p >> 5) & 31) * 255 / 31;
                    let r = ((p >> 10) & 31) * 255 / 31;
                    let a = !(((p >> 15) * 255) as u8);
                    out[i * 4..i * 4 + 4].copy_from_slice(&[r as u8, g as u8, b as u8, a]);
                }
            }
            U::La => {
                for i in 0..pixels {
                    let l = input[i * 2];
                    out[i * 4..i * 4 + 4].copy_from_slice(&[l, l, l, input[i * 2 + 1]]);
                }
            }
            U::LaPlanar => {
                for i in 0..pixels {
                    let l = input[i];
                    out[i * 4..i * 4 + 4].copy_from_slice(&[l, l, l, input[i + pixels]]);
                }
            }
            U::Map { step, src, invert } => {
                for i in 0..pixels {
                    let p = &input[i * step..];
                    for c in 0..4 {
                        let v = match src[c] {
                            Some(s) => p[s as usize],
                            None => 255,
                        };
                        out[i * 4 + c] = if invert[c] { !v } else { v };
                    }
                }
            }
            U::Band {
                ch,
                step,
                off,
                invert,
            } => {
                for i in 0..pixels {
                    let v = input[i * step + off];
                    out[i * 4 + ch] = if invert { !v } else { v };
                }
            }
            U::Planar4 => {
                let bands = self.bits / 8;
                for i in 0..pixels {
                    for c in 0..4 {
                        out[i * 4 + c] = if c < bands {
                            input[i + c * pixels]
                        } else {
                            255
                        };
                    }
                }
            }
            U::Rgb15 { bgr, alpha } => {
                for i in 0..pixels {
                    let p = input[i * 2] as u32 | (input[i * 2 + 1] as u32) << 8;
                    let a = (p & 31) * 255 / 31;
                    let b = ((p >> 5) & 31) * 255 / 31;
                    let c = ((p >> 10) & 31) * 255 / 31;
                    let (r, g, bl) = if bgr { (c, b, a) } else { (a, b, c) };
                    let al = if alpha { (p >> 15) * 255 } else { 255 };
                    out[i * 4..i * 4 + 4].copy_from_slice(&[r as u8, g as u8, bl as u8, al as u8]);
                }
            }
            U::Rgb16 { bgr } => {
                for i in 0..pixels {
                    let p = input[i * 2] as u32 | (input[i * 2 + 1] as u32) << 8;
                    let a = (p & 31) * 255 / 31;
                    let g = ((p >> 5) & 63) * 255 / 63;
                    let c = ((p >> 11) & 31) * 255 / 31;
                    let (r, bl) = if bgr { (c, a) } else { (a, c) };
                    out[i * 4..i * 4 + 4].copy_from_slice(&[r as u8, g as u8, bl as u8, 255]);
                }
            }
            U::Rgb4B { alpha } => {
                for i in 0..pixels {
                    let p = input[i * 2] as u32 | (input[i * 2 + 1] as u32) << 8;
                    let a = if alpha { ((p >> 12) & 15) * 17 } else { 255 };
                    out[i * 4..i * 4 + 4].copy_from_slice(&[
                        ((p & 15) * 17) as u8,
                        (((p >> 4) & 15) * 17) as u8,
                        (((p >> 8) & 15) * 17) as u8,
                        a as u8,
                    ]);
                }
            }
            U::Premul { step, src } => {
                for i in 0..pixels {
                    let p = &input[i * step..];
                    let a = p[src[3] as usize] as u32;
                    let px = if a == 0 {
                        [0, 0, 0, 0]
                    } else if a == 255 {
                        [
                            p[src[0] as usize],
                            p[src[1] as usize],
                            p[src[2] as usize],
                            255,
                        ]
                    } else {
                        let f = |v: u8| ((v as u32 * 255 / a).min(255)) as u8;
                        [
                            f(p[src[0] as usize]),
                            f(p[src[1] as usize]),
                            f(p[src[2] as usize]),
                            a as u8,
                        ]
                    };
                    out[i * 4..i * 4 + 4].copy_from_slice(&px);
                }
            }
            U::Cmyk2Rgb => {
                for i in 0..pixels {
                    let p = &input[i * 4..i * 4 + 4];
                    let nk = 255 - p[3] as i32;
                    let f = |v: u8| -> u8 {
                        let t = v as i32 * nk + 128;
                        (nk - (((t >> 8) + t) >> 8)).clamp(0, 255) as u8
                    };
                    out[i * 4..i * 4 + 4].copy_from_slice(&[f(p[0]), f(p[1]), f(p[2]), 255]);
                }
            }
            U::Num {
                bytes,
                big,
                signed,
                float_in,
                float_out,
            } => {
                for i in 0..pixels {
                    let s = &input[i * bytes..i * bytes + bytes];
                    let mut b = [0u8; 8];
                    for (j, v) in s.iter().enumerate() {
                        b[if big { bytes - 1 - j } else { j }] = *v;
                    }
                    let le = u64::from_le_bytes(b);
                    let o = &mut out[i * 4..i * 4 + 4];
                    if float_in {
                        let f = if bytes == 8 {
                            f64::from_bits(le) as f32
                        } else {
                            f32::from_bits(le as u32)
                        };
                        o.copy_from_slice(&f.to_le_bytes());
                        continue;
                    }
                    let v: i64 = if signed {
                        let sh = 64 - 8 * bytes as u32;
                        ((le << sh) as i64) >> sh
                    } else {
                        le as i64
                    };
                    if float_out {
                        o.copy_from_slice(&(v as f32).to_le_bytes());
                    } else {
                        o.copy_from_slice(&(v as i32).to_le_bytes());
                    }
                }
            }
            U::I16 { swap, flip } => {
                for i in 0..pixels {
                    let (mut a, mut b) = (input[i * 2], input[i * 2 + 1]);
                    if flip {
                        a = BITFLIP[a as usize];
                        b = BITFLIP[b as usize];
                    }
                    if swap {
                        std::mem::swap(&mut a, &mut b);
                    }
                    out[i * 2] = a;
                    out[i * 2 + 1] = b;
                }
            }
            U::I12 => {
                let mut i = 0;
                let mut inp = 0;
                while i + 1 < pixels {
                    let p = ((input[inp] as u16) << 4) + (input[inp + 1] >> 4) as u16;
                    out[i * 2..i * 2 + 2].copy_from_slice(&p.to_le_bytes());
                    let q = (((input[inp + 1] & 0x0f) as u16) << 8) + input[inp + 2] as u16;
                    out[i * 2 + 2..i * 2 + 4].copy_from_slice(&q.to_le_bytes());
                    i += 2;
                    inp += 3;
                }
                if i + 1 == pixels {
                    let p = ((input[inp] as u16) << 4) + (input[inp + 1] >> 4) as u16;
                    out[i * 2..i * 2 + 2].copy_from_slice(&p.to_le_bytes());
                }
            }
        }
    }
}
