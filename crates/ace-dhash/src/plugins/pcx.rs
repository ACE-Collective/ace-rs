//! PcxImagePlugin and DcxImagePlugin (the first PCX image of a DCX file).

use crate::Raise;
use crate::image::{Canvas, Mode, Palette};
use crate::io::{File, byte, u16le, u32le};
use crate::open::{Load, Opened, bomb_check};
use crate::unpack;

const MAXBLOCK: usize = 65536;

pub(crate) fn accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.len() >= 2 && p[0] == 10 && [0, 2, 3, 5].contains(&p[1]))
}

pub(crate) fn dcx_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.len() >= 4 && u32le(p, 0)? == 987654321)
}

pub(crate) fn open(data: &[u8]) -> Result<Opened<'_>, Raise> {
    open_at(data, 0, "PCX")
}

fn open_at<'a>(data: &'a [u8], at: usize, format: &'static str) -> Result<Opened<'a>, Raise> {
    let mut f = File::new(data);
    f.seek(at);
    let s = f.read(68);
    if !accept(s)? {
        return Err(Raise::syntax("not a PCX file"));
    }
    let bbox = (
        u16le(s, 4)? as i64,
        u16le(s, 6)? as i64,
        u16le(s, 8)? as i64 + 1,
        u16le(s, 10)? as i64 + 1,
    );
    if bbox.2 <= bbox.0 || bbox.3 <= bbox.1 {
        return Err(Raise::syntax("bad PCX image size"));
    }
    let offset = f.tell() + 60;
    let version = byte(s, 1)?;
    let bits = byte(s, 3)? as usize;
    let planes = byte(s, 65)? as usize;
    let provided = u16le(s, 66)? as usize;
    u16le(s, 12)?;
    u16le(s, 14)?;
    let (mode, rawmode, palette): (&str, String, Option<Vec<u8>>);
    if bits == 1 && planes == 1 {
        mode = "1";
        rawmode = "1".into();
        palette = None;
    } else if bits == 1 && (planes == 2 || planes == 4) {
        mode = "P";
        rawmode = format!("P;{planes}L");
        palette = Some(s[16..64].to_vec());
    } else if version == 5 && bits == 8 && planes == 1 {
        // fp.seek(-769, SEEK_END): a negative position is an OSError
        if data.len() < 769 {
            return Err(Raise::os("Invalid argument"));
        }
        let t = &data[data.len() - 769..];
        let mut m = "L";
        if t[0] == 12 {
            for i in 0..256 {
                if t[i * 3 + 1..i * 3 + 4] != [i as u8; 3] {
                    m = "P";
                    break;
                }
            }
        }
        mode = m;
        rawmode = m.into();
        palette = if m == "P" {
            Some(t[1..].to_vec())
        } else {
            None
        };
    } else if version == 5 && bits == 8 && planes == 3 {
        mode = "RGB";
        rawmode = "RGB;L".into();
        palette = None;
    } else {
        return Err(Raise::os("unknown PCX mode"));
    }
    let size = (bbox.2 - bbox.0, bbox.3 - bbox.1);
    let mut stride = (size.0 as usize * bits).div_ceil(8);
    if provided != stride {
        stride += stride % 2;
    }
    Ok(Opened::new(
        format,
        mode,
        size,
        Box::new(PcxLoad {
            data,
            mode,
            rawmode,
            palette,
            size,
            offset,
            bytes: planes * stride,
        }),
    ))
}

pub(crate) fn dcx_open(data: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(data);
    if !dcx_accept(f.read(4))? {
        return Err(Raise::syntax("not a DCX file"));
    }
    let mut offsets = Vec::new();
    for _ in 0..1024 {
        let o = u32le(f.read(4), 0)?;
        if o == 0 {
            break;
        }
        offsets.push(o as usize);
    }
    // seek(0): _seek_check raises EOFError when there are no frames
    let first = *offsets
        .first()
        .ok_or_else(|| Raise::eof("attempt to seek outside sequence"))?;
    let im = open_at(data, first, "DCX")?;
    bomb_check(im.size)?;
    Ok(im)
}

struct PcxLoad<'a> {
    data: &'a [u8],
    mode: &'static str,
    rawmode: String,
    palette: Option<Vec<u8>>,
    size: (i64, i64),
    offset: usize,
    bytes: usize,
}

impl Load for PcxLoad<'_> {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        let mode = Mode::from_name(self.mode).ok_or_else(Raise::key)?;
        let (w, h) = (self.size.0 as usize, self.size.1 as usize);
        let mut c = Canvas::new(mode, w, h)?;
        if let Some(p) = &self.palette {
            c.palette = Some(Palette::from_raw(p, 3, [0, 1, 2])?);
        }
        let u =
            unpack::find(mode, &self.rawmode).ok_or_else(|| Raise::value("unknown raw mode"))?;
        if (w * u.bits).div_ceil(8) > self.bytes {
            return Err(Raise::decoder(-1));
        }
        let bits = u.bits;
        let bands = match mode {
            Mode::Rgb => 3,
            _ => 1,
        };
        let mut buffer = vec![0u8; self.bytes.max(1)];
        let mut x = 0usize;
        let mut y = 0usize;
        let mut err = 0;
        let mut f = File::new(self.data);
        f.seek(self.offset);
        let mut b: Vec<u8> = Vec::new();
        'outer: loop {
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
                if b[p] & 0xC0 == 0xC0 {
                    if b.len() - p < 2 {
                        break;
                    }
                    let mut n = b[p] & 0x3F;
                    while n > 0 {
                        if x >= self.bytes {
                            err = -1;
                            break;
                        }
                        buffer[x] = b[p + 1];
                        x += 1;
                        n -= 1;
                    }
                    p += 2;
                } else {
                    buffer[x] = b[p];
                    x += 1;
                    p += 1;
                }
                if x >= self.bytes {
                    let (xs, nb) = if bits == 2 || bits == 4 {
                        (w.div_ceil(8), bits)
                    } else {
                        (w, bands)
                    };
                    let stride = self.bytes / nb;
                    if stride > xs {
                        for i in 1..nb {
                            buffer.copy_within(i * stride..i * stride + xs, i * xs);
                        }
                    }
                    c.unpack_row(&u, 0, y, &buffer, w);
                    x = 0;
                    y += 1;
                    if y >= h {
                        break 'outer;
                    }
                }
            }
            b.drain(..p);
        }
        if err < 0 {
            return Err(Raise::decoder(err));
        }
        Ok(c)
    }
}
