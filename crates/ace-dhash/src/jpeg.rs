//! The libjpeg-turbo 3.2.0 decoder as Pillow 13 drives it: `jpeg_read_header`, then
//! `jpeg_start_decompress` with fancy upsampling and the islow IDCT, `jpeg_read_scanlines`
//! and `jpeg_finish_decompress`, over a source that suspends (rather than inventing an EOI)
//! when the data runs out.
//!
//! Ported: the marker reader (jdmarker.c), the input controller (jdinput.c), sequential and
//! progressive Huffman decoding (jdhuff.c, jdphuff.c) with their handling of corrupt data
//! (zero fill after a marker, restart resynchronisation), the coefficient buffer, the islow
//! IDCT (jidctint.c, with the SIMD builds' 16-bit dequantisation), upsampling (jdsample.c,
//! with libjpeg's context rows at the image edges), and colour conversion (jdcolor.c).
//!
//! Not ported: arithmetic coding, lossless JPEG (SOF3, SOF11) and progressive block
//! smoothing, which libjpeg uses only for progressive files whose scans leave some of the
//! first AC coefficients unrefined. Those raise [`Kind::Unsupported`](crate::Kind).

use crate::Raise;
use crate::image::{Canvas, Mode};

const NATURAL_ORDER: [usize; 80] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63,
    63, 63, 63, 63, 63, 63,
];

const MIN_GET_BITS: i32 = 57;
const HUFF_LOOKAHEAD: i32 = 8;

/// The libjpeg outcome; the messages are libjpeg's, kept for debugging.
#[derive(Debug)]
#[allow(dead_code)]
enum E {
    /// The source ran out of data (fill_input_buffer returned FALSE).
    Suspend,
    /// ERREXIT: Pillow's setjmp handler, "broken data stream".
    Fatal(&'static str),
    /// Something this port does not do.
    Unsupported(&'static str),
}

type R<T> = Result<T, E>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ColorSpace {
    Gray,
    Rgb,
    YCbCr,
    Cmyk,
    Ycck,
    Unknown,
}

#[derive(Clone)]
struct HuffTbl {
    bits: [u8; 17],
    huffval: [u8; 256],
}

struct Derived {
    maxcode: [i64; 18],
    valoffset: [i64; 18],
    lookup: [i32; 256],
    huffval: [u8; 256],
}

/// jpeg_make_d_derived_tbl.
fn derive(t: Option<&HuffTbl>, is_dc: bool) -> R<Derived> {
    let t = t.ok_or(E::Fatal("Huffman table not defined"))?;
    let mut huffsize = [0u8; 257];
    let mut huffcode = [0u32; 257];
    let mut p = 0usize;
    for l in 1..=16 {
        let i = t.bits[l] as usize;
        if p + i > 256 {
            return Err(E::Fatal("Bogus Huffman table definition"));
        }
        for _ in 0..i {
            huffsize[p] = l as u8;
            p += 1;
        }
    }
    huffsize[p] = 0;
    let numsymbols = p;
    let mut code: u32 = 0;
    let mut si = huffsize[0] as u32;
    p = 0;
    while huffsize[p] != 0 {
        while huffsize[p] as u32 == si {
            huffcode[p] = code;
            p += 1;
            code += 1;
        }
        if code as u64 >= (1u64 << si) {
            return Err(E::Fatal("Bogus Huffman table definition"));
        }
        code <<= 1;
        si += 1;
    }
    let mut d = Derived {
        maxcode: [0; 18],
        valoffset: [0; 18],
        lookup: [0; 256],
        huffval: t.huffval,
    };
    p = 0;
    for l in 1..=16 {
        if t.bits[l] != 0 {
            d.valoffset[l] = p as i64 - huffcode[p] as i64;
            p += t.bits[l] as usize;
            d.maxcode[l] = huffcode[p - 1] as i64;
        } else {
            d.maxcode[l] = -1;
        }
    }
    d.valoffset[17] = 0;
    d.maxcode[17] = 0xFFFFF;
    for v in d.lookup.iter_mut() {
        *v = (HUFF_LOOKAHEAD + 1) << HUFF_LOOKAHEAD;
    }
    p = 0;
    for l in 1..=HUFF_LOOKAHEAD as usize {
        for _ in 1..=t.bits[l] as usize {
            let mut lookbits = (huffcode[p] as usize) << (HUFF_LOOKAHEAD as usize - l);
            for _ in 0..(1usize << (HUFF_LOOKAHEAD as usize - l)) {
                d.lookup[lookbits] = ((l as i32) << HUFF_LOOKAHEAD) | t.huffval[p] as i32;
                lookbits += 1;
            }
            p += 1;
        }
    }
    if is_dc {
        for i in 0..numsymbols {
            if t.huffval[i] > 15 {
                return Err(E::Fatal("Bogus Huffman table definition"));
            }
        }
    }
    Ok(d)
}

#[derive(Clone, Default)]
struct Comp {
    id: i32,
    index: usize,
    h: usize,
    v: usize,
    tq: usize,
    dc_tbl: usize,
    ac_tbl: usize,
    width_in_blocks: usize,
    height_in_blocks: usize,
    downsampled_width: usize,
    downsampled_height: usize,
    quant: Option<[i32; 64]>,
    needed: bool,
    /// Coefficients (multi-scan files), 64 a block in natural order.
    coefs: Vec<i16>,
    /// Samples after the IDCT, width_in_blocks * 8 by height_in_blocks * 8.
    plane: Vec<u8>,
    // per-scan
    mcu_width: usize,
    mcu_height: usize,
    last_col_width: usize,
    last_row_height: usize,
}

struct Dec<'a> {
    data: &'a [u8],
    pos: usize,
    // marker reader
    saw_soi: bool,
    saw_sof: bool,
    unread_marker: i32,
    next_restart_num: i32,
    // tables
    quant: [Option<[u16; 64]>; 4],
    dc_tbls: [Option<HuffTbl>; 4],
    ac_tbls: [Option<HuffTbl>; 4],
    restart_interval: usize,
    saw_jfif: bool,
    saw_adobe: bool,
    adobe_transform: u8,
    // frame
    progressive: bool,
    lossless: bool,
    arith: bool,
    precision: i32,
    width: usize,
    height: usize,
    comps: Vec<Comp>,
    max_h: usize,
    max_v: usize,
    has_multiple_scans: bool,
    inheaders: bool,
    eoi_reached: bool,
    input_scan_number: i32,
    // scan
    scan: Vec<usize>,
    ss: i32,
    se: i32,
    ah: i32,
    al: i32,
    coef_bits: Vec<[i32; 64]>,
    // entropy state
    get_buffer: u64,
    bits_left: i32,
    insufficient_data: bool,
}

impl<'a> Dec<'a> {
    fn byte(&mut self) -> R<i32> {
        let b = *self.data.get(self.pos).ok_or(E::Suspend)?;
        self.pos += 1;
        Ok(b as i32)
    }

    fn two(&mut self) -> R<i32> {
        let a = self.byte()?;
        let b = self.byte()?;
        Ok((a << 8) + b)
    }

    /// skip_input_data: past the end, the source suspends before more is read.
    fn skip(&mut self, n: i64) {
        if n > 0 {
            self.pos = self.pos.saturating_add(n as usize);
        }
    }

    fn next_marker(&mut self) -> R<()> {
        loop {
            let mut c = self.byte()?;
            while c != 0xFF {
                c = self.byte()?;
            }
            loop {
                c = self.byte()?;
                if c != 0xFF {
                    break;
                }
            }
            if c != 0 {
                self.unread_marker = c;
                return Ok(());
            }
        }
    }

    fn first_marker(&mut self) -> R<()> {
        let c = self.byte()?;
        let c2 = self.byte()?;
        if c != 0xFF || c2 != 0xD8 {
            return Err(E::Fatal("Not a JPEG file: starts with something else"));
        }
        self.unread_marker = c2;
        Ok(())
    }

    fn get_soi(&mut self) -> R<()> {
        if self.saw_soi {
            return Err(E::Fatal("Invalid JPEG file structure: two SOI markers"));
        }
        self.restart_interval = 0;
        self.saw_jfif = false;
        self.saw_adobe = false;
        self.adobe_transform = 0;
        self.saw_soi = true;
        Ok(())
    }

    fn get_sof(&mut self, prog: bool, lossless: bool, arith: bool) -> R<()> {
        if self.saw_sof {
            return Err(E::Fatal("Invalid JPEG file structure: two SOF markers"));
        }
        self.progressive = prog;
        self.lossless = lossless;
        self.arith = arith;
        let mut length = self.two()? as i64;
        self.precision = self.byte()?;
        self.height = self.two()? as usize;
        self.width = self.two()? as usize;
        let n = self.byte()? as usize;
        length -= 8;
        if self.height == 0 || self.width == 0 || n == 0 {
            return Err(E::Fatal("Empty JPEG image (DNL not supported)"));
        }
        if length != (n * 3) as i64 {
            return Err(E::Fatal("Bogus marker length"));
        }
        let mut comps = Vec::with_capacity(n);
        for ci in 0..n {
            let id = self.byte()?;
            let c = self.byte()? as usize;
            let tq = self.byte()? as usize;
            comps.push(Comp {
                id,
                index: ci,
                h: (c >> 4) & 15,
                v: c & 15,
                tq,
                needed: true,
                ..Default::default()
            });
        }
        self.comps = comps;
        self.saw_sof = true;
        Ok(())
    }

    fn get_sos(&mut self) -> R<()> {
        if !self.saw_sof {
            return Err(E::Fatal("Invalid JPEG file structure: SOS before SOF"));
        }
        let length = self.two()?;
        let n = self.byte()? as usize;
        if length != (n * 2 + 6) as i32 || n < 1 || n > 4 {
            return Err(E::Fatal("Bogus marker length"));
        }
        let mut cur: [Option<usize>; 4] = [None; 4];
        for i in 0..n {
            let cc = self.byte()?;
            let c = self.byte()? as usize;
            let mut found = None;
            for ci in 0..self.comps.len().min(4) {
                if cc == self.comps[ci].id && cur[ci].is_none() {
                    found = Some(ci);
                    break;
                }
            }
            let ci = found.ok_or(E::Fatal("Invalid component ID in SOS"))?;
            cur[i] = Some(ci);
            self.comps[ci].dc_tbl = (c >> 4) & 15;
            self.comps[ci].ac_tbl = c & 15;
            for pi in 0..i {
                if cur[pi] == Some(ci) {
                    return Err(E::Fatal("Invalid component ID in SOS"));
                }
            }
        }
        self.ss = self.byte()?;
        self.se = self.byte()?;
        let c = self.byte()?;
        self.ah = (c >> 4) & 15;
        self.al = c & 15;
        self.next_restart_num = 0;
        self.input_scan_number += 1;
        self.scan = cur[..n].iter().map(|c| c.expect("component")).collect();
        Ok(())
    }

    fn get_dht(&mut self) -> R<()> {
        let mut length = self.two()? as i64 - 2;
        while length > 16 {
            let mut index = self.byte()? as usize;
            let mut bits = [0u8; 17];
            let mut count = 0usize;
            for b in bits.iter_mut().skip(1) {
                *b = self.byte()? as u8;
                count += *b as usize;
            }
            length -= 17;
            if count > 256 || count as i64 > length {
                return Err(E::Fatal("Bogus Huffman table definition"));
            }
            let mut huffval = [0u8; 256];
            for v in huffval.iter_mut().take(count) {
                *v = self.byte()? as u8;
            }
            length -= count as i64;
            let t = HuffTbl { bits, huffval };
            if index & 0x10 != 0 {
                index -= 0x10;
                if index >= 4 {
                    return Err(E::Fatal("Bogus DHT index"));
                }
                self.ac_tbls[index] = Some(t);
            } else {
                if index >= 4 {
                    return Err(E::Fatal("Bogus DHT index"));
                }
                self.dc_tbls[index] = Some(t);
            }
        }
        if length != 0 {
            return Err(E::Fatal("Bogus marker length"));
        }
        Ok(())
    }

    fn get_dqt(&mut self) -> R<()> {
        let mut length = self.two()? as i64 - 2;
        while length > 0 {
            let n = self.byte()? as usize;
            let prec = n >> 4;
            let n = n & 0x0F;
            if n >= 4 {
                return Err(E::Fatal("Bogus DQT index"));
            }
            let mut q = self.quant[n].unwrap_or([0; 64]);
            for i in 0..64 {
                let v = if prec != 0 { self.two()? } else { self.byte()? };
                q[NATURAL_ORDER[i]] = v as u16;
                // a partially read table stays defined, as in libjpeg
                self.quant[n] = Some(q);
            }
            self.quant[n] = Some(q);
            length -= 65;
            if prec != 0 {
                length -= 64;
            }
        }
        if length != 0 {
            return Err(E::Fatal("Bogus marker length"));
        }
        Ok(())
    }

    fn get_dri(&mut self) -> R<()> {
        let length = self.two()?;
        if length != 4 {
            return Err(E::Fatal("Bogus marker length"));
        }
        self.restart_interval = self.two()? as usize;
        Ok(())
    }

    fn get_dac(&mut self) -> R<()> {
        let mut length = self.two()? as i64 - 2;
        while length > 0 {
            let index = self.byte()?;
            let val = self.byte()?;
            length -= 2;
            if !(0..8).contains(&index) {
                return Err(E::Fatal("Bogus DAC index"));
            }
            if index < 4 && (val & 0x0F) > (val >> 4) {
                return Err(E::Fatal("Bogus DAC value"));
            }
        }
        if length != 0 {
            return Err(E::Fatal("Bogus marker length"));
        }
        Ok(())
    }

    fn get_interesting_appn(&mut self) -> R<()> {
        let mut length = self.two()? as i64 - 2;
        let n = if length >= 14 {
            14
        } else if length > 0 {
            length as usize
        } else {
            0
        };
        let mut b = [0u8; 14];
        for v in b.iter_mut().take(n) {
            *v = self.byte()? as u8;
        }
        length -= n as i64;
        if self.unread_marker == 0xE0 {
            if n >= 14 && &b[..5] == b"JFIF\0" {
                self.saw_jfif = true;
            }
        } else if n >= 12 && &b[..5] == b"Adobe" {
            self.saw_adobe = true;
            self.adobe_transform = b[11];
        }
        self.skip(length);
        Ok(())
    }

    fn skip_variable(&mut self) -> R<()> {
        let length = self.two()? as i64 - 2;
        self.skip(length);
        Ok(())
    }

    /// read_markers: Ok(true) at SOS, Ok(false) at EOI.
    fn read_markers(&mut self) -> R<bool> {
        loop {
            if self.unread_marker == 0 {
                if !self.saw_soi {
                    self.first_marker()?;
                } else {
                    self.next_marker()?;
                }
            }
            match self.unread_marker {
                0xD8 => self.get_soi()?,
                0xC0 | 0xC1 => self.get_sof(false, false, false)?,
                0xC2 => self.get_sof(true, false, false)?,
                0xC3 => self.get_sof(false, true, false)?,
                0xC9 => self.get_sof(false, false, true)?,
                0xCA => self.get_sof(true, false, true)?,
                0xCB => self.get_sof(false, true, true)?,
                0xC5..=0xC8 | 0xCD..=0xCF => return Err(E::Fatal("Unsupported JPEG process")),
                0xDA => {
                    self.get_sos()?;
                    self.unread_marker = 0;
                    return Ok(true);
                }
                0xD9 => {
                    self.unread_marker = 0;
                    return Ok(false);
                }
                0xCC => self.get_dac()?,
                0xC4 => self.get_dht()?,
                0xDB => self.get_dqt()?,
                0xDD => self.get_dri()?,
                0xE0 | 0xEE => self.get_interesting_appn()?,
                0xE1..=0xED | 0xEF | 0xFE => self.skip_variable()?,
                0xD0..=0xD7 | 0x01 => {}
                0xDC => self.skip_variable()?,
                _ => return Err(E::Fatal("Unsupported marker type")),
            }
            self.unread_marker = 0;
        }
    }

    /// consume_markers: Ok(true) at an SOS, Ok(false) at EOI.
    fn consume_markers(&mut self) -> R<bool> {
        if self.eoi_reached {
            return Ok(false);
        }
        let sos = self.read_markers()?;
        if sos {
            if self.inheaders {
                self.initial_setup()?;
                self.inheaders = false;
            } else {
                if !self.has_multiple_scans {
                    return Err(E::Fatal("Didn't expect more than one scan"));
                }
                self.start_input_pass()?;
            }
        } else {
            self.eoi_reached = true;
            if self.inheaders && self.saw_sof {
                return Err(E::Fatal("Invalid JPEG file structure: missing SOS marker"));
            }
        }
        Ok(sos)
    }

    fn initial_setup(&mut self) -> R<()> {
        if self.height > 65500 || self.width > 65500 {
            return Err(E::Fatal(
                "Maximum supported image dimension is 65500 pixels",
            ));
        }
        if self.lossless {
            if !(2..=16).contains(&self.precision) {
                return Err(E::Fatal("Unsupported JPEG data precision"));
            }
        } else if self.precision != 8 && self.precision != 12 {
            return Err(E::Fatal("Unsupported JPEG data precision"));
        }
        if self.comps.len() > 10 {
            return Err(E::Fatal("Too many color components"));
        }
        self.max_h = 1;
        self.max_v = 1;
        for c in &self.comps {
            if c.h == 0 || c.h > 4 || c.v == 0 || c.v > 4 {
                return Err(E::Fatal("Bogus sampling factors"));
            }
            self.max_h = self.max_h.max(c.h);
            self.max_v = self.max_v.max(c.v);
        }
        let unit = if self.lossless { 1 } else { 8 };
        let (w, h, mh, mv) = (self.width, self.height, self.max_h, self.max_v);
        for c in &mut self.comps {
            c.width_in_blocks = (w * c.h).div_ceil(mh * unit);
            c.height_in_blocks = (h * c.v).div_ceil(mv * unit);
            c.downsampled_width = (w * c.h).div_ceil(mh);
            c.downsampled_height = (h * c.v).div_ceil(mv);
            c.needed = true;
            c.quant = None;
        }
        self.has_multiple_scans = self.scan.len() < self.comps.len() || self.progressive;
        Ok(())
    }

    fn per_scan_setup(&mut self) -> R<(usize, usize, Vec<usize>)> {
        if self.scan.len() == 1 {
            let c = &mut self.comps[self.scan[0]];
            c.mcu_width = 1;
            c.mcu_height = 1;
            c.last_col_width = 1;
            let t = c.height_in_blocks % c.v;
            c.last_row_height = if t == 0 { c.v } else { t };
            return Ok((c.width_in_blocks, c.height_in_blocks, vec![0]));
        }
        let mcus_per_row = self.width.div_ceil(self.max_h * 8);
        let mcu_rows = self.height.div_ceil(self.max_v * 8);
        let mut membership = Vec::new();
        for (si, &ci) in self.scan.iter().enumerate() {
            let c = &mut self.comps[ci];
            c.mcu_width = c.h;
            c.mcu_height = c.v;
            let t = c.width_in_blocks % c.h;
            c.last_col_width = if t == 0 { c.h } else { t };
            let t = c.height_in_blocks % c.v;
            c.last_row_height = if t == 0 { c.v } else { t };
            let blks = c.h * c.v;
            if membership.len() + blks > 10 {
                return Err(E::Fatal("Sampling factors too large for interleaved scan"));
            }
            membership.extend(std::iter::repeat_n(si, blks));
        }
        Ok((mcus_per_row, mcu_rows, membership))
    }

    fn latch_quant_tables(&mut self) -> R<()> {
        for &ci in &self.scan {
            if self.comps[ci].quant.is_some() {
                continue;
            }
            let q = self.comps[ci].tq;
            let t = self
                .quant
                .get(q)
                .copied()
                .flatten()
                .ok_or(E::Fatal("Quantization table not defined"))?;
            let mut m = [0i32; 64];
            for i in 0..64 {
                // ISLOW_MULT_TYPE is short in SIMD builds
                m[i] = t[i] as i16 as i32;
            }
            self.comps[ci].quant = Some(m);
        }
        Ok(())
    }

    fn start_input_pass(&mut self) -> R<()> {
        // per_scan_setup errors happen here; the geometry is recomputed by decode_scan
        self.per_scan_setup()?;
        self.latch_quant_tables()?;
        Ok(())
    }

    // ---------------------------------------------------------------- bit reading

    fn fill(&mut self, nbits: i32) -> R<()> {
        if self.unread_marker == 0 {
            while self.bits_left < MIN_GET_BITS {
                let mut c = self.byte()?;
                if c == 0xFF {
                    loop {
                        c = self.byte()?;
                        if c != 0xFF {
                            break;
                        }
                    }
                    if c == 0 {
                        c = 0xFF;
                    } else {
                        self.unread_marker = c;
                        return self.no_more_bytes(nbits);
                    }
                }
                self.get_buffer = (self.get_buffer << 8) | c as u64;
                self.bits_left += 8;
            }
            Ok(())
        } else {
            self.no_more_bytes(nbits)
        }
    }

    fn no_more_bytes(&mut self, nbits: i32) -> R<()> {
        if nbits > self.bits_left {
            self.insufficient_data = true;
            self.get_buffer <<= (MIN_GET_BITS - self.bits_left) as u32;
            self.bits_left = MIN_GET_BITS;
        }
        Ok(())
    }

    fn check(&mut self, n: i32) -> R<()> {
        if self.bits_left < n {
            self.fill(n)?;
        }
        Ok(())
    }

    fn get_bits(&mut self, n: i32) -> i32 {
        self.bits_left -= n;
        ((self.get_buffer >> self.bits_left as u32) & ((1u64 << n) - 1)) as i32
    }

    fn huff_decode(&mut self, t: &Derived) -> R<i32> {
        let nb;
        if self.bits_left < HUFF_LOOKAHEAD {
            self.fill(0)?;
            if self.bits_left < HUFF_LOOKAHEAD {
                nb = 1;
                return self.huff_slow(t, nb);
            }
        }
        let look = ((self.get_buffer >> (self.bits_left - HUFF_LOOKAHEAD) as u32) & 0xFF) as usize;
        nb = t.lookup[look] >> HUFF_LOOKAHEAD;
        if nb <= HUFF_LOOKAHEAD {
            self.bits_left -= nb;
            return Ok(t.lookup[look] & 0xFF);
        }
        self.huff_slow(t, nb)
    }

    fn huff_slow(&mut self, t: &Derived, min_bits: i32) -> R<i32> {
        let mut l = min_bits as usize;
        self.check(l as i32)?;
        let mut code = self.get_bits(l as i32) as i64;
        while code > t.maxcode[l] {
            code <<= 1;
            self.check(1)?;
            code |= self.get_bits(1) as i64;
            l += 1;
        }
        if l > 16 {
            return Ok(0);
        }
        Ok(t.huffval[((code + t.valoffset[l]) & 0xFF) as usize] as i32)
    }

    fn process_restart(&mut self) -> R<()> {
        self.bits_left = 0;
        if self.unread_marker == 0 {
            self.next_marker()?;
        }
        if self.unread_marker == 0xD0 + self.next_restart_num {
            self.unread_marker = 0;
        } else {
            self.resync_to_restart(self.next_restart_num)?;
        }
        self.next_restart_num = (self.next_restart_num + 1) & 7;
        if self.unread_marker == 0 {
            self.insufficient_data = false;
        }
        Ok(())
    }

    fn resync_to_restart(&mut self, desired: i32) -> R<()> {
        let mut marker = self.unread_marker;
        loop {
            let action = if marker < 0xC0 {
                2
            } else if !(0xD0..=0xD7).contains(&marker) {
                3
            } else if marker == 0xD0 + ((desired + 1) & 7) || marker == 0xD0 + ((desired + 2) & 7) {
                3
            } else if marker == 0xD0 + ((desired - 1) & 7) || marker == 0xD0 + ((desired - 2) & 7) {
                2
            } else {
                1
            };
            match action {
                1 => {
                    self.unread_marker = 0;
                    return Ok(());
                }
                2 => {
                    self.next_marker()?;
                    marker = self.unread_marker;
                }
                _ => return Ok(()),
            }
        }
    }
}

/// jdcoefct.c's smoothing_ok: whether libjpeg would smooth the blocks of this image.
fn smoothing_ok(d: &Dec) -> bool {
    let mut useful = false;
    for c in &d.comps {
        let Some(q) = c.quant else {
            return false;
        };
        if [0, 1, 8, 16, 9, 2, 3, 10, 17, 24]
            .iter()
            .any(|&i| q[i] == 0)
        {
            return false;
        }
        let cb = &d.coef_bits[c.index];
        if cb[0] < 0 {
            return false;
        }
        if cb[1..10].iter().any(|&b| b != 0) {
            useful = true;
        }
    }
    useful
}

fn extend(x: i32, s: i32) -> i32 {
    if x < (1 << (s - 1)) {
        x.wrapping_add(((-1i32) << s).wrapping_add(1))
    } else {
        x
    }
}

/// Where each block of an MCU goes: (component, block column, block row) or None for a
/// dummy block outside the component.
fn mcu_blocks(
    d: &Dec,
    mcus_per_row: usize,
    mcu_col: usize,
    mcu_row: usize,
) -> Vec<(usize, usize, usize, bool)> {
    let mut v = Vec::new();
    if d.scan.len() == 1 {
        v.push((d.scan[0], mcu_col, mcu_row, true));
        return v;
    }
    let _ = mcus_per_row;
    for &ci in &d.scan {
        let c = &d.comps[ci];
        for y in 0..c.mcu_height {
            for x in 0..c.mcu_width {
                let bx = mcu_col * c.mcu_width + x;
                let by = mcu_row * c.mcu_height + y;
                let real = bx < c.width_in_blocks && by < c.height_in_blocks;
                v.push((ci, bx, by, real));
            }
        }
    }
    v
}

/// One scan's entropy decoding. `single`: decode straight into planes (single-scan file).
fn decode_scan(d: &mut Dec, single: bool) -> R<()> {
    if d.arith {
        return Err(E::Unsupported("arithmetic-coded JPEG"));
    }
    if d.lossless {
        return Err(E::Unsupported("lossless JPEG"));
    }
    let (mcus_per_row, mcu_rows, membership) = d.per_scan_setup()?;
    // entropy start_pass
    let mut dc_t: Vec<Option<Derived>> = (0..4).map(|_| None).collect();
    let mut ac_t: Vec<Option<Derived>> = (0..4).map(|_| None).collect();
    let progressive = d.progressive;
    let (ss, se, ah, al) = (d.ss, d.se, d.ah, d.al);
    let is_dc_band = ss == 0;
    if progressive {
        let mut bad = false;
        if is_dc_band {
            if se != 0 {
                bad = true;
            }
        } else {
            if ss > se || se >= 64 {
                bad = true;
            }
            if d.scan.len() != 1 {
                bad = true;
            }
        }
        if ah != 0 && al != ah - 1 {
            bad = true;
        }
        if al > 13 {
            bad = true;
        }
        if bad {
            return Err(E::Fatal("Invalid progressive parameters"));
        }
        let ncomp = d.comps.len();
        for &ci in &d.scan.clone() {
            let cindex = d.comps[ci].index;
            for coefi in ss.min(1)..=se.max(9) {
                let cur = d.coef_bits[cindex][coefi as usize];
                d.coef_bits[cindex + ncomp][coefi as usize] =
                    if d.input_scan_number > 1 { cur } else { 0 };
            }
            for coefi in ss..=se {
                d.coef_bits[cindex][coefi as usize] = al;
            }
        }
        for &ci in &d.scan.clone() {
            let c = &d.comps[ci];
            if is_dc_band {
                if ah == 0 {
                    let t = c.dc_tbl;
                    dc_t[t] = Some(derive(d.dc_tbls[t].as_ref(), true)?);
                }
            } else {
                let t = c.ac_tbl;
                ac_t[t] = Some(derive(d.ac_tbls[t].as_ref(), false)?);
            }
        }
    } else {
        for &ci in &d.scan.clone() {
            let (dt, at) = (d.comps[ci].dc_tbl, d.comps[ci].ac_tbl);
            dc_t[dt] = Some(derive(d.dc_tbls[dt].as_ref(), true)?);
            ac_t[at] = Some(derive(d.ac_tbls[at].as_ref(), false)?);
        }
    }
    let ac_band_tbl = if progressive && !is_dc_band {
        d.comps[d.scan[0]].ac_tbl
    } else {
        0
    };
    d.bits_left = 0;
    d.get_buffer = 0;
    d.insufficient_data = false;
    let mut last_dc = [0i32; 4];
    let mut eobrun: u32 = 0;
    let mut restarts_to_go = d.restart_interval;
    let _ = membership;
    for mcu_row in 0..mcu_rows {
        for mcu_col in 0..mcus_per_row {
            if d.restart_interval != 0 {
                if restarts_to_go == 0 {
                    d.process_restart()?;
                    last_dc = [0; 4];
                    eobrun = 0;
                    restarts_to_go = d.restart_interval;
                }
            }
            let blocks = mcu_blocks(d, mcus_per_row, mcu_col, mcu_row);
            if !progressive {
                // decode_mcu (sequential); a skipped MCU leaves zero blocks
                let decode = !d.insufficient_data;
                for &(ci, bx, by, real) in &blocks {
                    let mut block = [0i16; 64];
                    if decode {
                        let si = d.scan.iter().position(|&c| c == ci).expect("scan comp");
                        let dct = dc_t[d.comps[ci].dc_tbl].as_ref().expect("dc table");
                        let mut s = d.huff_decode(dct)?;
                        if s != 0 {
                            d.check(s)?;
                            let r = d.get_bits(s);
                            s = extend(r, s);
                        }
                        s = s.wrapping_add(last_dc[si]);
                        last_dc[si] = s;
                        block[0] = s as i16;
                        let act = ac_t[d.comps[ci].ac_tbl].as_ref().expect("ac table");
                        let mut k = 1usize;
                        while k < 64 {
                            let s = d.huff_decode(act)?;
                            let r = (s >> 4) as usize;
                            let s = s & 15;
                            if s != 0 {
                                k += r;
                                d.check(s)?;
                                let v = d.get_bits(s);
                                block[NATURAL_ORDER[k]] = extend(v, s) as i16;
                            } else {
                                if r != 15 {
                                    break;
                                }
                                k += 15;
                            }
                            k += 1;
                        }
                    }
                    if real {
                        store_block(d, ci, bx, by, &block, single);
                    }
                }
            } else {
                decode_progressive_mcu(
                    d,
                    &blocks,
                    &dc_t,
                    &ac_t,
                    ac_band_tbl,
                    &mut last_dc,
                    &mut eobrun,
                )?;
            }
            if d.restart_interval != 0 {
                restarts_to_go = restarts_to_go.wrapping_sub(1);
            }
        }
    }
    Ok(())
}

fn coef_slice<'b>(d: &'b mut Dec, ci: usize, bx: usize, by: usize) -> &'b mut [i16] {
    let c = &mut d.comps[ci];
    let i = (by * c.width_in_blocks + bx) * 64;
    &mut c.coefs[i..i + 64]
}

fn decode_progressive_mcu(
    d: &mut Dec,
    blocks: &[(usize, usize, usize, bool)],
    dc_t: &[Option<Derived>],
    ac_t: &[Option<Derived>],
    ac_tbl: usize,
    last_dc: &mut [i32; 4],
    eobrun: &mut u32,
) -> R<()> {
    let (ss, se, ah, al) = (d.ss, d.se, d.ah, d.al);
    // Dummy blocks of an interleaved MCU are decoded into a scratch block.
    let mut scratch = [0i16; 64];
    if ss == 0 {
        if ah == 0 {
            if d.insufficient_data {
                return Ok(());
            }
            for &(ci, bx, by, real) in blocks {
                let si = d.scan.iter().position(|&c| c == ci).expect("scan comp");
                let t = dc_t[d.comps[ci].dc_tbl].as_ref().expect("dc table");
                let mut s = d.huff_decode(t)?;
                if s != 0 {
                    d.check(s)?;
                    let r = d.get_bits(s);
                    s = extend(r, s);
                }
                let last = last_dc[si];
                if (last >= 0 && s > i32::MAX - last) || (last < 0 && s < i32::MIN - last) {
                    return Err(E::Fatal("DCT coefficient out of range"));
                }
                s += last;
                last_dc[si] = s;
                let v = ((s as u32) << al) as i32 as i16;
                if real {
                    coef_slice(d, ci, bx, by)[0] = v;
                } else {
                    scratch[0] = v;
                }
            }
        } else {
            let p1 = 1i16 << al;
            for &(ci, bx, by, real) in blocks {
                d.check(1)?;
                if d.get_bits(1) != 0 {
                    if real {
                        coef_slice(d, ci, bx, by)[0] |= p1;
                    } else {
                        scratch[0] |= p1;
                    }
                }
            }
        }
        return Ok(());
    }
    if d.insufficient_data {
        return Ok(());
    }
    let (ci, bx, by, _) = blocks[0];
    let t = ac_t[ac_tbl].as_ref().expect("ac table");
    let mut blk = {
        let s = coef_slice(d, ci, bx, by);
        let mut b = [0i16; 64];
        b.copy_from_slice(s);
        b
    };
    let r = if ah == 0 {
        ac_first(d, t, &mut blk, ss, se, al, eobrun)
    } else {
        ac_refine(d, t, &mut blk, ss, se, al, eobrun)
    };
    // On suspension the whole decode fails, so a partial block is never kept.
    r?;
    coef_slice(d, ci, bx, by).copy_from_slice(&blk);
    Ok(())
}

fn ac_first(
    d: &mut Dec,
    t: &Derived,
    blk: &mut [i16; 64],
    ss: i32,
    se: i32,
    al: i32,
    eobrun: &mut u32,
) -> R<()> {
    if *eobrun > 0 {
        *eobrun -= 1;
        return Ok(());
    }
    let mut k = ss;
    while k <= se {
        let s = d.huff_decode(t)?;
        let mut r = s >> 4;
        let s = s & 15;
        if s != 0 {
            k += r;
            d.check(s)?;
            let v = d.get_bits(s);
            let v = extend(v, s);
            blk[NATURAL_ORDER[k as usize]] = ((v as u32) << al) as i32 as i16;
        } else if r == 15 {
            k += 15;
        } else {
            let mut e = 1u32 << r;
            if r != 0 {
                d.check(r)?;
                r = d.get_bits(r);
                e += r as u32;
            }
            *eobrun = e - 1;
            break;
        }
        k += 1;
    }
    Ok(())
}

fn ac_refine(
    d: &mut Dec,
    t: &Derived,
    blk: &mut [i16; 64],
    ss: i32,
    se: i32,
    al: i32,
    eobrun: &mut u32,
) -> R<()> {
    let p1: i16 = 1i16.wrapping_shl(al as u32);
    let m1: i16 = (-1i16).wrapping_shl(al as u32);
    let mut k = ss;
    if *eobrun == 0 {
        while k <= se {
            let s = d.huff_decode(t)?;
            let mut r = s >> 4;
            let mut s = s & 15;
            if s != 0 {
                d.check(1)?;
                s = if d.get_bits(1) != 0 {
                    p1 as i32
                } else {
                    m1 as i32
                };
            } else if r != 15 {
                let mut e = 1u32 << r;
                if r != 0 {
                    d.check(r)?;
                    r = d.get_bits(r);
                    e += r as u32;
                }
                *eobrun = e;
                break;
            }
            loop {
                let pos = NATURAL_ORDER[k as usize];
                if blk[pos] != 0 {
                    d.check(1)?;
                    if d.get_bits(1) != 0 && (blk[pos] & p1) == 0 {
                        if blk[pos] >= 0 {
                            blk[pos] = blk[pos].wrapping_add(p1);
                        } else {
                            blk[pos] = blk[pos].wrapping_add(m1);
                        }
                    }
                } else {
                    r -= 1;
                    if r < 0 {
                        break;
                    }
                }
                k += 1;
                if k > se {
                    break;
                }
            }
            if s != 0 {
                let pos = NATURAL_ORDER[k as usize];
                blk[pos] = s as i16;
            }
            k += 1;
        }
    }
    if *eobrun > 0 {
        while k <= se {
            let pos = NATURAL_ORDER[k as usize];
            if blk[pos] != 0 {
                d.check(1)?;
                if d.get_bits(1) != 0 && (blk[pos] & p1) == 0 {
                    if blk[pos] >= 0 {
                        blk[pos] = blk[pos].wrapping_add(p1);
                    } else {
                        blk[pos] = blk[pos].wrapping_add(m1);
                    }
                }
            }
            k += 1;
        }
        *eobrun -= 1;
    }
    Ok(())
}

fn store_block(d: &mut Dec, ci: usize, bx: usize, by: usize, block: &[i16; 64], single: bool) {
    if single {
        let c = &mut d.comps[ci];
        let q = c.quant.expect("latched");
        let stride = c.width_in_blocks * 8;
        idct_islow(block, &q, &mut c.plane, by * 8 * stride + bx * 8, stride);
    } else {
        coef_slice(d, ci, bx, by).copy_from_slice(block);
    }
}

// ---------------------------------------------------------------- IDCT

const CONST_BITS: i32 = 13;
const PASS1_BITS: i32 = 2;
const FIX_0_298631336: i64 = 2446;
const FIX_0_390180644: i64 = 3196;
const FIX_0_541196100: i64 = 4433;
const FIX_0_765366865: i64 = 6270;
const FIX_0_899976223: i64 = 7373;
const FIX_1_175875602: i64 = 9633;
const FIX_1_501321110: i64 = 12299;
const FIX_1_847759065: i64 = 15137;
const FIX_1_961570560: i64 = 16069;
const FIX_2_053119869: i64 = 16819;
const FIX_2_562915447: i64 = 20995;
const FIX_3_072711026: i64 = 25172;

fn descale(x: i64, n: i32) -> i64 {
    (x + (1i64 << (n - 1))) >> n
}

/// The NEON second pass's output (libjpeg-turbo's SIMD builds, as Pillow's wheels use):
/// the high 16 bits of the sum (vaddhn), a saturating rounding shift by 2 to 8 bits
/// (vqrshrn), plus 128. This equals the C code's range-limited DESCALE(x, 18) whenever the
/// value is in range; out of range the C code wraps where NEON saturates.
fn idct_limit(x: i64) -> u8 {
    let hi = ((x as i32) >> 16) as i16 as i32;
    (((hi + 2) >> 2).clamp(-128, 127) + 128) as u8
}

fn idct_islow(coef: &[i16; 64], q: &[i32; 64], out: &mut [u8], at: usize, stride: usize) {
    let mut ws = [0i32; 64];
    let deq = |i: usize| -> i64 { coef[i].wrapping_mul(q[i] as i16) as i64 };
    for c in 0..8 {
        if (1..8).all(|r| coef[r * 8 + c] == 0) {
            // NEON: vshl_n_s16 on the 16-bit product
            let dc = ((deq(c) as i16).wrapping_shl(PASS1_BITS as u32)) as i32;
            for r in 0..8 {
                ws[r * 8 + c] = dc;
            }
            continue;
        }
        let z2 = deq(16 + c);
        let z3 = deq(48 + c);
        let z1 = (z2 + z3) * FIX_0_541196100;
        let tmp2 = z1 + z3 * -FIX_1_847759065;
        let tmp3 = z1 + z2 * FIX_0_765366865;
        let z2 = deq(c);
        let z3 = deq(32 + c);
        let tmp0 = (z2 + z3) << CONST_BITS;
        let tmp1 = (z2 - z3) << CONST_BITS;
        let tmp10 = tmp0 + tmp3;
        let tmp13 = tmp0 - tmp3;
        let tmp11 = tmp1 + tmp2;
        let tmp12 = tmp1 - tmp2;
        let (t0, t1, t2, t3) = (deq(56 + c), deq(40 + c), deq(24 + c), deq(8 + c));
        let (o0, o1, o2, o3) = odd(t0, t1, t2, t3);
        let n = CONST_BITS - PASS1_BITS;
        // NEON: vrshrn_n_s32 narrows to 16 bits
        let p1 = |x: i64| descale(x as i32 as i64, n) as i16 as i32;
        ws[c] = p1(tmp10 + o3);
        ws[56 + c] = p1(tmp10 - o3);
        ws[8 + c] = p1(tmp11 + o2);
        ws[48 + c] = p1(tmp11 - o2);
        ws[16 + c] = p1(tmp12 + o1);
        ws[40 + c] = p1(tmp12 - o1);
        ws[24 + c] = p1(tmp13 + o0);
        ws[32 + c] = p1(tmp13 - o0);
    }
    for r in 0..8 {
        let w = &ws[r * 8..r * 8 + 8];
        let o = &mut out[at + r * stride..at + r * stride + 8];
        let z2 = w[2] as i64;
        let z3 = w[6] as i64;
        let z1 = (z2 + z3) * FIX_0_541196100;
        let tmp2 = z1 + z3 * -FIX_1_847759065;
        let tmp3 = z1 + z2 * FIX_0_765366865;
        let tmp0 = (w[0] as i64 + w[4] as i64) << CONST_BITS;
        let tmp1 = (w[0] as i64 - w[4] as i64) << CONST_BITS;
        let tmp10 = tmp0 + tmp3;
        let tmp13 = tmp0 - tmp3;
        let tmp11 = tmp1 + tmp2;
        let tmp12 = tmp1 - tmp2;
        let (o0, o1, o2, o3) = odd(w[7] as i64, w[5] as i64, w[3] as i64, w[1] as i64);
        o[0] = idct_limit(tmp10 + o3);
        o[7] = idct_limit(tmp10 - o3);
        o[1] = idct_limit(tmp11 + o2);
        o[6] = idct_limit(tmp11 - o2);
        o[2] = idct_limit(tmp12 + o1);
        o[5] = idct_limit(tmp12 - o1);
        o[3] = idct_limit(tmp13 + o0);
        o[4] = idct_limit(tmp13 - o0);
    }
}

fn odd(tmp0: i64, tmp1: i64, tmp2: i64, tmp3: i64) -> (i64, i64, i64, i64) {
    let z1 = tmp0 + tmp3;
    let z2 = tmp1 + tmp2;
    let z3 = tmp0 + tmp2;
    let z4 = tmp1 + tmp3;
    let z5 = (z3 + z4) * FIX_1_175875602;
    let mut tmp0 = tmp0 * FIX_0_298631336;
    let mut tmp1 = tmp1 * FIX_2_053119869;
    let mut tmp2 = tmp2 * FIX_3_072711026;
    let mut tmp3 = tmp3 * FIX_1_501321110;
    let z1 = z1 * -FIX_0_899976223;
    let z2 = z2 * -FIX_2_562915447;
    let z3 = z3 * -FIX_1_961570560 + z5;
    let z4 = z4 * -FIX_0_390180644 + z5;
    tmp0 += z1 + z3;
    tmp1 += z2 + z4;
    tmp2 += z2 + z3;
    tmp3 += z1 + z4;
    (tmp0, tmp1, tmp2, tmp3)
}

// ---------------------------------------------------------------- output

#[derive(Clone, Copy)]
enum Up {
    Full,
    H2v1Fancy,
    H2v1,
    H1v2Fancy,
    H2v2Fancy,
    H2v2,
    Int(usize, usize),
}

/// One upsampled sample of a component: output column `x`, output row `y`.
/// Context rows outside the component are its first and last rows, as libjpeg's main
/// buffer controller arranges; fancy filters stop at `downsampled_width`.
fn upsample_row(c: &Comp, up: Up, max_v: usize, y: usize, out: &mut [u8]) {
    let stride = c.width_in_blocks * 8;
    let dh = c.downsampled_height;
    let row = |i: isize| -> &[u8] {
        let i = i.clamp(0, dh as isize - 1) as usize;
        &c.plane[i * stride..(i + 1) * stride]
    };
    let dw = c.downsampled_width;
    match up {
        Up::Full => {
            let r = &c.plane[y * stride..];
            let n = out.len().min(stride);
            out[..n].copy_from_slice(&r[..n]);
        }
        Up::H2v1 | Up::H2v2 | Up::Int(..) => {
            let (he, ve) = match up {
                Up::H2v1 => (2, 1),
                Up::H2v2 => (2, 2),
                Up::Int(h, v) => (h, v),
                _ => unreachable!(),
            };
            let r = &c.plane[(y / ve) * stride..];
            for (x, o) in out.iter_mut().enumerate() {
                *o = r[x / he];
            }
        }
        Up::H2v1Fancy => {
            let r = &c.plane[y * stride..];
            fancy_h(r, dw, out);
        }
        Up::H1v2Fancy | Up::H2v2Fancy => {
            // input row group of v_in rows makes max_v output rows, two per input row
            let v_in = max_v / 2;
            let group = y / max_v;
            let within = y % max_v;
            let inrow = group * v_in + within / 2;
            let v = within % 2;
            let near = row(inrow as isize);
            let far = row(if v == 0 {
                inrow as isize - 1
            } else {
                inrow as isize + 1
            });
            if let Up::H1v2Fancy = up {
                let bias = if v == 0 { 1 } else { 2 };
                for x in 0..dw.min(out.len()) {
                    out[x] = ((near[x] as i32 * 3 + far[x] as i32 + bias) >> 2) as u8;
                }
            } else {
                let cs = |i: usize| near[i] as i32 * 3 + far[i] as i32;
                let mut o = 0;
                let mut put = |o: &mut usize, v: i32| {
                    if *o < out.len() {
                        out[*o] = v as u8;
                    }
                    *o += 1;
                };
                let mut this = cs(0);
                let next = cs(1);
                put(&mut o, (this * 4 + 8) >> 4);
                put(&mut o, (this * 3 + next + 7) >> 4);
                let mut last = this;
                this = next;
                for i in 2..dw {
                    let next = cs(i);
                    put(&mut o, (this * 3 + last + 8) >> 4);
                    put(&mut o, (this * 3 + next + 7) >> 4);
                    last = this;
                    this = next;
                }
                put(&mut o, (this * 3 + last + 8) >> 4);
                put(&mut o, (this * 4 + 7) >> 4);
            }
        }
    }
}

fn fancy_h(r: &[u8], dw: usize, out: &mut [u8]) {
    let mut o = 0usize;
    let mut put = |v: i32| {
        if o < out.len() {
            out[o] = v as u8;
        }
        o += 1;
    };
    let first = r[0] as i32;
    put(first);
    put((first * 3 + r[1] as i32 + 2) >> 2);
    for i in 1..dw - 1 {
        let v = r[i] as i32 * 3;
        put((v + r[i - 1] as i32 + 1) >> 2);
        put((v + r[i + 1] as i32 + 2) >> 2);
    }
    let last = r[dw - 1] as i32;
    put((last * 3 + r[dw - 2] as i32 + 1) >> 2);
    put(last);
}

fn select_upsampler(c: &Comp, max_h: usize, max_v: usize) -> R<Up> {
    let (hi, vi) = (c.h, c.v);
    Ok(if hi == max_h && vi == max_v {
        Up::Full
    } else if hi * 2 == max_h && vi == max_v {
        if c.downsampled_width > 2 {
            Up::H2v1Fancy
        } else {
            Up::H2v1
        }
    } else if hi == max_h && vi * 2 == max_v {
        Up::H1v2Fancy
    } else if hi * 2 == max_h && vi * 2 == max_v {
        if c.downsampled_width > 2 {
            Up::H2v2Fancy
        } else {
            Up::H2v2
        }
    } else if max_h % hi == 0 && max_v % vi == 0 {
        Up::Int(max_h / hi, max_v / vi)
    } else {
        return Err(E::Fatal("Fractional sampling not implemented yet"));
    })
}

struct YccTables {
    cr_r: [i32; 256],
    cb_b: [i32; 256],
    cr_g: [i64; 256],
    cb_g: [i64; 256],
}

fn ycc_tables() -> YccTables {
    let fix = |x: f64| -> i64 { (x * 65536.0 + 0.5) as i64 };
    let mut t = YccTables {
        cr_r: [0; 256],
        cb_b: [0; 256],
        cr_g: [0; 256],
        cb_g: [0; 256],
    };
    for i in 0..256 {
        let x = i as i64 - 128;
        t.cr_r[i] = ((fix(1.40200) * x + 32768) >> 16) as i32;
        t.cb_b[i] = ((fix(1.77200) * x + 32768) >> 16) as i32;
        t.cr_g[i] = -fix(0.71414) * x;
        t.cb_g[i] = -fix(0.34414) * x + 32768;
    }
    t
}

fn clamp8(v: i32) -> u8 {
    v.clamp(0, 255) as u8
}

/// Pillow's `ImagingJpegDecode` over the whole file.
pub(crate) fn decode(data: &[u8], canvas: &mut Canvas) -> Result<(), Raise> {
    match run(data, canvas) {
        Ok(()) => Ok(()),
        Err(E::Suspend) => Err(Raise::truncated()),
        Err(E::Fatal(_)) => Err(Raise::decoder(-2)),
        Err(E::Unsupported(m)) => Err(Raise::unsupported(m)),
    }
}

fn new_dec(data: &[u8]) -> Dec<'_> {
    Dec {
        data,
        pos: 0,
        saw_soi: false,
        saw_sof: false,
        unread_marker: 0,
        next_restart_num: 0,
        quant: [None; 4],
        dc_tbls: [None, None, None, None],
        ac_tbls: [None, None, None, None],
        restart_interval: 0,
        saw_jfif: false,
        saw_adobe: false,
        adobe_transform: 0,
        progressive: false,
        lossless: false,
        arith: false,
        precision: 8,
        width: 0,
        height: 0,
        comps: Vec::new(),
        max_h: 1,
        max_v: 1,
        has_multiple_scans: false,
        inheaders: true,
        eoi_reached: false,
        input_scan_number: 0,
        scan: Vec::new(),
        ss: 0,
        se: 0,
        ah: 0,
        al: 0,
        coef_bits: Vec::new(),
        get_buffer: 0,
        bits_left: 0,
        insufficient_data: false,
    }
}

fn run(data: &[u8], canvas: &mut Canvas) -> R<()> {
    let mut d = new_dec(data);
    // jpeg_read_header(FALSE), repeated while it finds only tables
    loop {
        if d.consume_markers()? {
            break;
        }
        // tables only: jpeg_abort, then read on from here
        d.saw_soi = false;
        d.saw_sof = false;
        d.unread_marker = 0;
        d.eoi_reached = false;
        d.inheaders = true;
        d.comps.clear();
        d.input_scan_number = 0;
    }
    // default_decompress_parms
    let n = d.comps.len();
    let jcs = match n {
        1 => ColorSpace::Gray,
        3 => {
            if d.saw_jfif {
                ColorSpace::YCbCr
            } else if d.saw_adobe {
                if d.adobe_transform == 0 {
                    ColorSpace::Rgb
                } else {
                    ColorSpace::YCbCr
                }
            } else {
                let (a, b, c) = (d.comps[0].id, d.comps[1].id, d.comps[2].id);
                if (a, b, c) == (1, 2, 3) {
                    if d.lossless {
                        ColorSpace::Rgb
                    } else {
                        ColorSpace::YCbCr
                    }
                } else if (a, b, c) == (82, 71, 66) {
                    ColorSpace::Rgb
                } else if d.lossless {
                    ColorSpace::Rgb
                } else {
                    ColorSpace::YCbCr
                }
            }
        }
        4 => {
            if d.saw_adobe {
                if d.adobe_transform == 0 {
                    ColorSpace::Cmyk
                } else {
                    ColorSpace::Ycck
                }
            } else {
                ColorSpace::Cmyk
            }
        }
        _ => ColorSpace::Unknown,
    };
    // Pillow's out_color_space from the rawmode
    let out = match canvas.mode {
        Mode::L => ColorSpace::Gray,
        Mode::Rgb => ColorSpace::Rgb,
        _ => ColorSpace::Cmyk,
    };
    // jinit_color_deconverter checks
    match jcs {
        ColorSpace::Gray if n != 1 => return Err(E::Fatal("Bogus input colorspace")),
        ColorSpace::YCbCr | ColorSpace::Rgb if n != 3 => {
            return Err(E::Fatal("Bogus input colorspace"));
        }
        ColorSpace::Ycck | ColorSpace::Cmyk if n != 4 => {
            return Err(E::Fatal("Bogus input colorspace"));
        }
        _ => {}
    }
    let ok = match out {
        ColorSpace::Gray => matches!(jcs, ColorSpace::Gray | ColorSpace::YCbCr | ColorSpace::Rgb),
        ColorSpace::Rgb => matches!(jcs, ColorSpace::YCbCr | ColorSpace::Gray | ColorSpace::Rgb),
        _ => matches!(jcs, ColorSpace::Ycck | ColorSpace::Cmyk),
    };
    if !ok {
        return Err(E::Fatal("Unsupported color conversion request"));
    }
    if d.arith {
        return Err(E::Unsupported("arithmetic-coded JPEG"));
    }
    if d.lossless {
        return Err(E::Unsupported("lossless JPEG"));
    }
    if d.precision != 8 {
        return Err(E::Fatal("Unsupported JPEG data precision"));
    }
    // memory: planes (and coefficients for multi-scan files)
    let blocks: usize = d
        .comps
        .iter()
        .map(|c| c.width_in_blocks * c.height_in_blocks)
        .sum();
    if blocks.saturating_mul(64) > 4 * crate::MAX_CANVAS_PIXELS {
        return Err(E::Fatal("image too large"));
    }
    let ups: Vec<Up> = d
        .comps
        .iter()
        .map(|c| select_upsampler(c, d.max_h, d.max_v))
        .collect::<R<_>>()?;
    for c in &mut d.comps {
        c.plane = vec![0u8; c.width_in_blocks * 64 * c.height_in_blocks];
    }
    if d.progressive {
        d.coef_bits = vec![[-1i32; 64]; n * 2];
    }
    d.start_input_pass()?;
    let multi = d.has_multiple_scans;
    if multi {
        for c in &mut d.comps {
            c.coefs = vec![0i16; c.width_in_blocks * c.height_in_blocks * 64];
        }
    }
    decode_scan(&mut d, !multi)?;
    if multi {
        // jpeg_start_decompress absorbs the whole file
        loop {
            if d.consume_markers()? {
                decode_scan(&mut d, false)?;
            } else {
                break;
            }
        }
        if d.progressive {
            if smoothing_ok(&d) {
                return Err(E::Unsupported("progressive JPEG needing block smoothing"));
            }
        }
        for ci in 0..n {
            let c = &mut d.comps[ci];
            let q = c.quant.unwrap_or([0; 64]);
            let stride = c.width_in_blocks * 8;
            for by in 0..c.height_in_blocks {
                for bx in 0..c.width_in_blocks {
                    let i = (by * c.width_in_blocks + bx) * 64;
                    let mut blk = [0i16; 64];
                    blk.copy_from_slice(&c.coefs[i..i + 64]);
                    idct_islow(&blk, &q, &mut c.plane, by * 8 * stride + bx * 8, stride);
                }
            }
            c.coefs = Vec::new();
        }
    }
    // output
    let w = d.width;
    let t = ycc_tables();
    let mut rows: Vec<Vec<u8>> = vec![vec![0u8; w.next_multiple_of(d.max_h) + 16]; n];
    let mut px = vec![0u8; w * 4];
    let gray_only = out == ColorSpace::Gray;
    for y in 0..d.height.min(canvas.h) {
        for ci in 0..n {
            if gray_only && ci > 0 {
                break;
            }
            let c = &d.comps[ci];
            upsample_row(c, ups[ci], d.max_v, y, &mut rows[ci][..w]);
        }
        match (jcs, out) {
            (_, ColorSpace::Gray) => {
                px[..w].copy_from_slice(&rows[0][..w]);
            }
            (ColorSpace::YCbCr, ColorSpace::Rgb) => {
                for x in 0..w {
                    let (yy, cb, cr) =
                        (rows[0][x] as i32, rows[1][x] as usize, rows[2][x] as usize);
                    px[x * 4] = clamp8(yy + t.cr_r[cr]);
                    px[x * 4 + 1] = clamp8(yy + ((t.cb_g[cb] + t.cr_g[cr]) >> 16) as i32);
                    px[x * 4 + 2] = clamp8(yy + t.cb_b[cb]);
                    px[x * 4 + 3] = 255;
                }
            }
            (ColorSpace::Rgb, ColorSpace::Rgb) => {
                for x in 0..w {
                    px[x * 4..x * 4 + 4]
                        .copy_from_slice(&[rows[0][x], rows[1][x], rows[2][x], 255]);
                }
            }
            (ColorSpace::Gray, ColorSpace::Rgb) => {
                for x in 0..w {
                    let v = rows[0][x];
                    px[x * 4..x * 4 + 4].copy_from_slice(&[v, v, v, 255]);
                }
            }
            (ColorSpace::Ycck, _) => {
                for x in 0..w {
                    let (yy, cb, cr) =
                        (rows[0][x] as i32, rows[1][x] as usize, rows[2][x] as usize);
                    // CMYK;I: Pillow inverts every byte
                    px[x * 4] = !clamp8(255 - (yy + t.cr_r[cr]));
                    px[x * 4 + 1] = !clamp8(255 - (yy + ((t.cb_g[cb] + t.cr_g[cr]) >> 16) as i32));
                    px[x * 4 + 2] = !clamp8(255 - (yy + t.cb_b[cb]));
                    px[x * 4 + 3] = !rows[3][x];
                }
            }
            _ => {
                for x in 0..w {
                    px[x * 4..x * 4 + 4].copy_from_slice(&[
                        !rows[0][x],
                        !rows[1][x],
                        !rows[2][x],
                        !rows[3][x],
                    ]);
                }
            }
        }
        let n_px = w.min(canvas.w);
        canvas.put_row(0, y, &px, n_px);
    }
    if !multi {
        // jpeg_finish_decompress: read on to EOI; running out of data is fine here
        // (one call: consume_markers reads markers until EOI, and raises at an SOS)
        match d.consume_markers() {
            Ok(_) | Err(E::Suspend) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
