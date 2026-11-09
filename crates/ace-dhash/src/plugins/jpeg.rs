//! JpegImagePlugin: Pillow's marker scan in `_open`; the pixels come from `crate::jpeg`, a
//! port of the libjpeg-turbo decoder Pillow calls.

use crate::Raise;
use crate::image::{Canvas, Mode};
use crate::io::{File, byte, u16be};
use crate::open::{Load, Opened};

pub(crate) fn accept(prefix: &[u8]) -> Result<bool, Raise> {
    Ok(prefix.starts_with(b"\xff\xd8\xff"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Handler {
    None,
    Skip,
    App,
    Com,
    Sof,
    Dqt,
}

fn marker(i: u16) -> Option<Handler> {
    use Handler as H;
    Some(match i {
        0xFFC4 | 0xFFCC | 0xFFDA | 0xFFDC | 0xFFDD | 0xFFDF => H::Skip,
        0xFFC0..=0xFFCF if i != 0xFFC8 => H::Sof,
        0xFFC8 => H::None,
        0xFFD0..=0xFFD9 => H::None,
        0xFFDB => H::Dqt,
        0xFFDE => H::Sof,
        0xFFE0..=0xFFEF => H::App,
        0xFFF0..=0xFFFD => H::None,
        0xFFFE => H::Com,
        _ => return None,
    })
}

fn len_n(f: &mut File) -> Result<i64, Raise> {
    Ok(u16be(f.read(2), 0)? as i64 - 2)
}

fn safe_read<'a>(f: &mut File<'a>, n: i64) -> Result<&'a [u8], Raise> {
    if n <= 0 {
        return Ok(&[]);
    }
    f.safe_read(n as usize)
}

pub(crate) fn open(data: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(data);
    if !accept(f.read(3))? {
        return Err(Raise::syntax("not a JPEG file"));
    }
    let mut s: Vec<u8> = vec![0xff];
    let mut mode = "";
    let mut size = (0i64, 0i64);
    let mut icclist: Vec<Vec<u8>> = Vec::new();
    let mut tile = false;
    while !s.is_empty() {
        let mut i = s[0] as u16;
        if i == 0xFF {
            s.extend_from_slice(f.read(1));
            if s.len() < 2 {
                break;
            }
            i = u16be(&s, 0)?;
        } else {
            s = f.read(1).to_vec();
            continue;
        }
        if let Some(h) = marker(i) {
            match h {
                Handler::None => {}
                Handler::Skip | Handler::Com => {
                    let n = len_n(&mut f)?;
                    safe_read(&mut f, n)?;
                }
                Handler::App => {
                    let n = len_n(&mut f)?;
                    let s = safe_read(&mut f, n)?;
                    app(i, s, &mut icclist)?;
                }
                Handler::Sof => {
                    let n = len_n(&mut f)?;
                    let s = safe_read(&mut f, n)?;
                    size = (u16be(s, 3)? as i64, u16be(s, 1)? as i64);
                    if byte(s, 0)? != 8 {
                        return Err(Raise::syntax("cannot handle non 8-bit layers"));
                    }
                    mode = match byte(s, 5)? {
                        1 => "L",
                        3 => "RGB",
                        4 => "CMYK",
                        _ => return Err(Raise::syntax("cannot handle this many layers")),
                    };
                    if !icclist.is_empty() {
                        icclist.sort();
                        byte(&icclist[0], 13)?;
                        icclist.clear();
                    }
                    let mut k = 6;
                    while k < s.len() {
                        let t = &s[k..(k + 3).min(s.len())];
                        byte(t, 0)?;
                        byte(t, 1)?;
                        byte(t, 2)?;
                        k += 3;
                    }
                }
                Handler::Dqt => {
                    let n = len_n(&mut f)?;
                    let mut s = safe_read(&mut f, n)?;
                    while !s.is_empty() {
                        let v = s[0];
                        let precision = if v / 16 == 0 { 1 } else { 2 };
                        let qt_length = 1 + precision * 64;
                        if s.len() < qt_length {
                            return Err(Raise::syntax("bad quantization table marker"));
                        }
                        s = &s[qt_length..];
                    }
                }
            }
            if i == 0xFFDA {
                tile = true;
                break;
            }
            s = f.read(1).to_vec();
        } else if i == 0 || i == 0xFFFF {
            s = vec![0xff];
        } else if i == 0xFF00 {
            s = f.read(1).to_vec();
        } else {
            return Err(Raise::syntax("no marker found"));
        }
    }
    Ok(Opened::new(
        "JPEG",
        mode,
        size,
        Box::new(JpegLoad {
            data,
            mode,
            size,
            tile,
        }),
    ))
}

/// The APP handler's parsing, for the exceptions it can raise.
fn app(marker: u16, s: &[u8], icclist: &mut Vec<Vec<u8>>) -> Result<(), Raise> {
    if marker == 0xFFE0 && s.starts_with(b"JFIF") {
        u16be(s, 5)?;
    } else if marker == 0xFFE2 && s.starts_with(b"ICC_PROFILE\0") {
        icclist.push(s.to_vec());
    } else if marker == 0xFFED && s.starts_with(b"Photoshop 3.0\x00") {
        let mut off = 14usize;
        while s.get(off..off + 4) == Some(b"8BIM") {
            off += 4;
            let Ok(code) = u16be(s, off) else {
                return Ok(());
            };
            off += 2;
            let name_len = byte(s, off)? as usize;
            off += 1 + name_len;
            off += off & 1;
            let Ok(size) = crate::io::u32be(s, off) else {
                return Ok(());
            };
            off += 4;
            let end = off.saturating_add(size as usize).min(s.len());
            let data_len = end.saturating_sub(off);
            if code == 0x03ED && data_len < 14 {
                // struct.error, caught: the loop ends
                return Ok(());
            }
            off = off.saturating_add(size as usize);
            off += off & 1;
        }
    } else if marker == 0xFFEE && s.starts_with(b"Adobe") {
        u16be(s, 5)?;
    }
    Ok(())
}

struct JpegLoad<'a> {
    data: &'a [u8],
    mode: &'static str,
    size: (i64, i64),
    tile: bool,
}

impl Load for JpegLoad<'_> {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        if !self.tile {
            return Err(Raise::os("cannot load this image"));
        }
        let mode = Mode::from_name(self.mode).ok_or_else(Raise::key)?;
        let (w, h) = (self.size.0 as usize, self.size.1 as usize);
        let mut c = Canvas::new(mode, w, h)?;
        crate::jpeg::decode(self.data, &mut c)?;
        Ok(c)
    }
}
