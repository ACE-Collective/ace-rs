//! GifImagePlugin: the first frame, which is what `Image.open` leaves loaded.

use crate::Raise;
use crate::image::{Canvas, Mode, Palette};
use crate::io::{File, byte, u16le};
use crate::open::{Load, Opened, bomb_check};

const MAXBLOCK: usize = 65536;

pub(crate) fn accept(prefix: &[u8]) -> Result<bool, Raise> {
    Ok(prefix.starts_with(b"GIF87a") || prefix.starts_with(b"GIF89a"))
}

/// `_is_palette_needed`: IndexError on a palette cut short mid-entry.
fn palette_needed(p: &[u8]) -> Result<bool, Raise> {
    let mut i = 0;
    while i < p.len() {
        let (a, b, c) = (byte(p, i)?, byte(p, i + 1)?, byte(p, i + 2)?);
        let n = i / 3;
        if !(n == a as usize && a == b && b == c) {
            return Ok(true);
        }
        i += 3;
    }
    Ok(false)
}

/// `GifImageFile.data()`.
fn data<'a>(f: &mut File<'a>) -> Option<&'a [u8]> {
    let s = f.read(1);
    if !s.is_empty() && s[0] != 0 {
        return Some(f.read(s[0] as usize));
    }
    None
}

pub(crate) fn open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut f = File::new(d);
    let s = f.read(13);
    if !accept(s)? {
        return Err(Raise::syntax("not a GIF file"));
    }
    let mut size = (u16le(s, 6)? as i64, u16le(s, 8)? as i64);
    let flags = byte(s, 10)?;
    let mut global = None;
    if flags & 128 != 0 {
        let bits = (flags & 7) + 1;
        let p = f.read(3 << bits);
        if palette_needed(p)? {
            global = Some(p.to_vec());
        }
    }
    // _seek(0)
    let mut s = f.read(1);
    if s.is_empty() || s == b";" {
        return Err(Raise::eof("no more images in GIF file"));
    }
    let mut frame_transparency = None;
    // None: no local palette; Some(None): a local palette that is a gray ramp.
    let mut local: Option<Option<Vec<u8>>> = None;
    let mut extent = None;
    let mut lzw_bits = 0u8;
    let mut offset = 0usize;
    loop {
        if s.is_empty() {
            s = f.read(1);
        }
        if s.is_empty() || s == b";" {
            break;
        }
        if s == b"!" {
            let t = f.read(1);
            let block = data(&mut f);
            let kind = byte(t, 0)?;
            if kind == 249 && block.is_some() {
                let block = block.unwrap_or_default();
                let fl = byte(block, 0)?;
                if fl & 1 != 0 {
                    frame_transparency = Some(byte(block, 3)?);
                }
                u16le(block, 1)?;
            } else if kind == 254 {
                let mut b = block;
                while b.is_some_and(|b| !b.is_empty()) {
                    b = data(&mut f);
                }
                s = &[];
                continue;
            } else if kind == 255 && block.is_some() {
                if block.unwrap_or_default().starts_with(b"NETSCAPE2.0") {
                    let b = data(&mut f);
                    if let Some(b) = b {
                        if b.len() >= 3 && b[0] == 1 {
                            u16le(b, 1)?;
                        }
                    }
                }
            }
            while data(&mut f).is_some() {}
        } else if s == b"," {
            let t = f.read(9);
            let x0 = u16le(t, 0)? as i64;
            let y0 = u16le(t, 2)? as i64;
            let x1 = x0 + u16le(t, 4)? as i64;
            let y1 = y0 + u16le(t, 6)? as i64;
            if x1 > size.0 || y1 > size.1 {
                let ns = (x1.max(size.0), y1.max(size.1));
                bomb_check(ns)?;
                size = ns;
            }
            extent = Some((x0, y0, x1, y1));
            let fl = byte(t, 8)?;
            let interlace = fl & 64 != 0;
            if fl & 128 != 0 {
                let bits = (fl & 7) + 1;
                let p = f.read(3 << bits);
                local = Some(if palette_needed(p)? {
                    Some(p.to_vec())
                } else {
                    None
                });
            }
            lzw_bits = byte(f.read(1), 0)?;
            offset = f.tell();
            let (x0, y0, x1, y1) = extent.expect("extent");
            let frame_palette: Option<Vec<u8>> = match &local {
                Some(l) => l.clone(),
                None => global.clone(),
            };
            let mode = if frame_palette.is_some() { "P" } else { "L" };
            // self.palette: the local palette if needed, else a copy of the global one.
            let palette = match &local {
                Some(Some(l)) => Some(l.clone()),
                _ => global.clone(),
            };
            return Ok(Opened::new(
                "GIF",
                mode,
                size,
                Box::new(GifLoad {
                    data: d,
                    size,
                    mode,
                    palette,
                    transparency: frame_transparency,
                    extent: (x0, y0, x1, y1),
                    interlace,
                    bits: lzw_bits,
                    offset,
                }),
            ));
        }
        s = &[];
    }
    let _ = (extent, lzw_bits, offset);
    Err(Raise::eof("image not found in GIF frame"))
}

struct GifLoad<'a> {
    data: &'a [u8],
    size: (i64, i64),
    mode: &'static str,
    palette: Option<Vec<u8>>,
    transparency: Option<u8>,
    extent: (i64, i64, i64, i64),
    interlace: bool,
    bits: u8,
    offset: usize,
}

impl Load for GifLoad<'_> {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        let mode = if self.mode == "P" { Mode::P } else { Mode::L };
        let (w, h) = (self.size.0 as usize, self.size.1 as usize);
        let mut c = match self.transparency {
            Some(t) => Canvas::filled(mode, w, h, &[t])?,
            None => Canvas::new(mode, w, h)?,
        };
        if let Some(p) = &self.palette {
            c.palette = Some(Palette::from_raw(p, 3, [0, 1, 2])?);
        }
        let (x0, y0, x1, y1) = self.extent;
        super::raw::check_extents(&c, x0, y0, x1, y1)?;
        let mut dec = GifDecoder::new(
            self.bits as i32,
            self.interlace,
            (x0 as usize, y0 as usize, x1 as usize, y1 as usize),
        );
        let mut f = File::new(self.data);
        f.seek(self.offset);
        let mut b: Vec<u8> = Vec::new();
        loop {
            let s = f.read(MAXBLOCK);
            if s.is_empty() {
                return Err(Raise::truncated());
            }
            b.extend_from_slice(s);
            match dec.decode(&b, &mut c) {
                Step::Used(n) => {
                    b.drain(..n);
                }
                Step::Done(code) => {
                    if code < 0 {
                        return Err(Raise::decoder(code));
                    }
                    break;
                }
            }
        }
        if mode == Mode::L && self.palette.is_some() {
            // Image.load puts the palette on the "L" core image, which becomes "P" under
            // a "L" image; resize then raises ValueError("image has wrong mode").
            return Err(Raise::value("image has wrong mode"));
        }
        Ok(c)
    }
}

pub(crate) enum Step {
    Used(usize),
    Done(i32),
}

const GIFBITS: i32 = 12;
const GIFTABLE: usize = 1 << GIFBITS;

/// Pillow's GifDecode.c.
pub(crate) struct GifDecoder {
    bits: i32,
    started: bool,
    state: u8,
    clear: i32,
    end: i32,
    next: i32,
    codesize: i32,
    codemask: i32,
    bitbuffer: u32,
    bitcount: i32,
    blocksize: i32,
    interlace: u8,
    step: usize,
    lastdata: u8,
    lastcode: i32,
    buffer: Vec<u8>,
    bufferindex: usize,
    data: Vec<u8>,
    link: Vec<u16>,
    x: usize,
    y: usize,
    xoff: usize,
    yoff: usize,
    xsize: usize,
    ysize: usize,
}

impl GifDecoder {
    pub(crate) fn new(bits: i32, interlace: bool, ext: (usize, usize, usize, usize)) -> Self {
        GifDecoder {
            bits,
            started: false,
            state: 0,
            clear: 0,
            end: 0,
            next: 0,
            codesize: 0,
            codemask: 0,
            bitbuffer: 0,
            bitcount: 0,
            blocksize: 0,
            interlace: interlace as u8,
            step: 1,
            lastdata: 0,
            lastcode: 0,
            buffer: vec![0; GIFTABLE],
            bufferindex: GIFTABLE,
            data: vec![0; GIFTABLE],
            link: vec![0; GIFTABLE],
            x: 0,
            y: 0,
            xoff: ext.0,
            yoff: ext.1,
            xsize: ext.2 - ext.0,
            ysize: ext.3 - ext.1,
        }
    }

    /// NEWLINE: false when the image is complete.
    fn newline(&mut self) -> bool {
        self.x = 0;
        self.y += self.step;
        while self.y >= self.ysize {
            match self.interlace {
                1 => {
                    self.y = 4;
                    self.interlace = 2;
                }
                2 => {
                    self.step = 4;
                    self.y = 2;
                    self.interlace = 3;
                }
                3 => {
                    self.step = 2;
                    self.y = 1;
                    self.interlace = 0;
                }
                _ => return false,
            }
        }
        true
    }

    pub(crate) fn decode(&mut self, buf: &[u8], im: &mut Canvas) -> Step {
        let mut ptr = 0usize;
        if !self.started {
            if self.bits < 0 || self.bits > 12 {
                return Step::Done(-8);
            }
            self.clear = 1 << self.bits;
            self.end = self.clear + 1;
            if self.interlace != 0 {
                self.interlace = 1;
                self.step = 8;
            } else {
                self.step = 1;
            }
            self.state = 1;
            self.started = true;
        }
        let mut one = [0u8; 1];
        loop {
            if self.state == 1 {
                self.next = self.clear + 2;
                self.codesize = self.bits + 1;
                self.codemask = (1 << self.codesize) - 1;
                self.bufferindex = GIFTABLE;
                self.state = 2;
            }
            let (start, len, from_buffer);
            if self.bufferindex < GIFTABLE {
                start = self.bufferindex;
                len = GIFTABLE - self.bufferindex;
                self.bufferindex = GIFTABLE;
                from_buffer = true;
            } else {
                while self.bitcount < self.codesize {
                    if self.blocksize > 0 {
                        let c = buf[ptr];
                        ptr += 1;
                        self.blocksize -= 1;
                        self.bitbuffer |= (c as u32) << self.bitcount;
                        self.bitcount += 8;
                    } else {
                        if ptr >= buf.len() {
                            return Step::Used(ptr);
                        }
                        let c = buf[ptr] as usize;
                        if buf.len() - ptr < c + 1 {
                            return Step::Used(ptr);
                        }
                        self.blocksize = c as i32;
                        ptr += 1;
                    }
                }
                let mut c = (self.bitbuffer as i32) & self.codemask;
                self.bitbuffer >>= self.codesize;
                self.bitcount -= self.codesize;
                if c == self.clear {
                    if self.state != 2 {
                        self.state = 1;
                    }
                    continue;
                }
                if c == self.end {
                    return Step::Used(ptr);
                }
                if self.state == 2 {
                    if c > self.clear {
                        return Step::Done(-2);
                    }
                    self.lastdata = c as u8;
                    self.lastcode = c;
                    self.state = 3;
                } else {
                    let thiscode = c;
                    if c > self.next {
                        return Step::Done(-2);
                    }
                    if c == self.next {
                        if self.bufferindex == 0 {
                            return Step::Done(-2);
                        }
                        self.bufferindex -= 1;
                        self.buffer[self.bufferindex] = self.lastdata;
                        c = self.lastcode;
                    }
                    while c >= self.clear {
                        if self.bufferindex == 0 || c as usize >= GIFTABLE {
                            return Step::Done(-2);
                        }
                        self.bufferindex -= 1;
                        self.buffer[self.bufferindex] = self.data[c as usize];
                        c = self.link[c as usize] as i32;
                    }
                    self.lastdata = c as u8;
                    if (self.next as usize) < GIFTABLE {
                        self.data[self.next as usize] = c as u8;
                        self.link[self.next as usize] = self.lastcode as u16;
                        if self.next == self.codemask && self.codesize < GIFBITS {
                            self.codesize += 1;
                            self.codemask = (1 << self.codesize) - 1;
                        }
                        self.next += 1;
                    }
                    self.lastcode = thiscode;
                }
                start = 0;
                len = 1;
                from_buffer = false;
            }
            if self.y >= self.ysize {
                return Step::Done(-1);
            }
            one[0] = self.lastdata;
            for k in 0..len {
                let v = if from_buffer {
                    self.buffer[start + k]
                } else {
                    one[0]
                };
                im.put(self.xoff + self.x, self.yoff + self.y, &[v]);
                self.x += 1;
                if self.x >= self.xsize && !self.newline() {
                    return Step::Done(0);
                }
            }
        }
    }
}
