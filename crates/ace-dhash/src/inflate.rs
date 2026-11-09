//! A zlib stream inflater that stops, continues and fails where zlib's `inflate()` does.
//!
//! Pillow's PNG decoder calls `inflate(Z_NO_FLUSH)` with room for one row at a time and stops
//! once the last row is out. Whether a bad checksum or a bad code just after the last row is
//! seen depends on how far zlib goes with a full output buffer: it keeps reading block headers,
//! end-of-block codes, length and distance codes and the trailer while input lasts, and stops
//! before writing a literal or a match. This follows zlib's state machine (inflate.c), so the
//! same input pieces give the same output and the same errors. Byte consumption may differ
//! from zlib's (it reads ahead in inflate_fast), which nothing here observes.

const ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];
const LBASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEXT: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DBASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DEXT: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

const FAST_BITS: u32 = 9;

#[derive(Clone)]
struct Huffman {
    count: [u16; 16],
    symbol: Vec<u16>,
    max_len: u32,
    /// zlib's table for a code with no symbols (inflate_table's `max == 0`).
    empty: bool,
    fast: Vec<u16>,
}

enum Decoded {
    Need,
    Sym(u16, u32),
    Invalid(u32),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Codes,
    Lens,
    Dists,
}

impl Huffman {
    /// zlib's inflate_table: Err for an over-subscribed set, or an incomplete one (allowed only
    /// for a literal/length or distance code of a single one-bit code).
    fn build(lens: &[u8], kind: Kind) -> Result<Huffman, ()> {
        let mut count = [0u16; 16];
        for &l in lens {
            count[l as usize] += 1;
        }
        let max_len = (1..16).rev().find(|&l| count[l] != 0).unwrap_or(0) as u32;
        if max_len == 0 {
            return Ok(Huffman {
                count,
                symbol: Vec::new(),
                max_len: 0,
                empty: true,
                fast: Vec::new(),
            });
        }
        let mut left: i32 = 1;
        for &c in &count[1..16] {
            left <<= 1;
            left -= c as i32;
            if left < 0 {
                return Err(());
            }
        }
        if left > 0 && (kind == Kind::Codes || max_len != 1) {
            return Err(());
        }
        let mut offs = [0u16; 16];
        for l in 1..15 {
            offs[l + 1] = offs[l] + count[l];
        }
        let mut symbol = vec![0u16; lens.len()];
        for (s, &l) in lens.iter().enumerate() {
            if l != 0 {
                symbol[offs[l as usize] as usize] = s as u16;
                offs[l as usize] += 1;
            }
        }
        // The fast table: codes of up to FAST_BITS bits, indexed by their bits as read.
        let mut fast = vec![0u16; 1 << FAST_BITS];
        let mut code: u32 = 0;
        let mut idx = 0usize;
        for len in 1..=15u32 {
            for _ in 0..count[len as usize] {
                if len <= FAST_BITS {
                    let rev = (code.reverse_bits() >> (32 - len)) as usize;
                    let step = 1usize << len;
                    let mut i = rev;
                    while i < fast.len() {
                        fast[i] = ((len as u16) << 9) | symbol[idx];
                        i += step;
                    }
                }
                code += 1;
                idx += 1;
            }
            code <<= 1;
        }
        Ok(Huffman {
            count,
            symbol,
            max_len,
            empty: false,
            fast,
        })
    }

    fn decode(&self, hold: u64, bits: u32) -> Decoded {
        if self.empty {
            return if bits >= 1 {
                Decoded::Invalid(1)
            } else {
                Decoded::Need
            };
        }
        let f = self.fast[(hold & ((1 << FAST_BITS) - 1)) as usize];
        if f != 0 {
            let len = (f >> 9) as u32;
            return if len <= bits {
                Decoded::Sym(f & 0x1ff, len)
            } else {
                Decoded::Need
            };
        }
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..=15u32 {
            if len > bits {
                return Decoded::Need;
            }
            code |= ((hold >> (len - 1)) & 1) as i32;
            let count = self.count[len as usize] as i32;
            if code - count < first {
                return Decoded::Sym(self.symbol[(index + (code - first)) as usize], len);
            }
            if len >= self.max_len {
                return Decoded::Invalid(len);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Decoded::Invalid(15)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Head,
    Dict,
    Type,
    Stored,
    Copy,
    Table,
    LenLens,
    CodeLens,
    Len,
    LenExt,
    Dist,
    DistExt,
    Match,
    Lit,
    Check,
    Done,
    Bad,
}

/// What a call to `inflate` ended with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Status {
    Ok,
    StreamEnd,
    NeedDict,
    DataError(&'static str),
}

pub(crate) struct Inflate {
    state: State,
    hold: u64,
    bits: u32,
    last: bool,
    length: usize,
    offset: usize,
    extra: u32,
    nlen: usize,
    ndist: usize,
    ncode: usize,
    have: usize,
    lens: [u8; 320],
    codes: Option<Huffman>,
    lcode: Option<Huffman>,
    dcode: Option<Huffman>,
    window: Vec<u8>,
    wpos: usize,
    total: u64,
    a: u32,
    b: u32,
    msg: &'static str,
    /// Expect a zlib header and trailer (else a raw deflate stream).
    zlib: bool,
}

const WSIZE: usize = 32768;

impl Inflate {
    pub(crate) fn new() -> Self {
        Self::with_header(true)
    }

    pub(crate) fn with_header(zlib: bool) -> Self {
        Inflate {
            state: if zlib { State::Head } else { State::Type },
            hold: 0,
            bits: 0,
            last: false,
            length: 0,
            offset: 0,
            extra: 0,
            nlen: 0,
            ndist: 0,
            ncode: 0,
            have: 0,
            lens: [0; 320],
            codes: None,
            lcode: None,
            dcode: None,
            window: vec![0; WSIZE],
            wpos: 0,
            total: 0,
            a: 1,
            b: 0,
            msg: "",
            zlib,
        }
    }

    fn emit(&mut self, out: &mut [u8], put: &mut usize, byte: u8) {
        out[*put] = byte;
        *put += 1;
        self.window[self.wpos] = byte;
        self.wpos = (self.wpos + 1) & (WSIZE - 1);
        self.total += 1;
        self.a = (self.a + byte as u32) % 65521;
        self.b = (self.b + self.a) % 65521;
    }

    fn bad(&mut self, msg: &'static str) {
        self.msg = msg;
        self.state = State::Bad;
    }

    /// `inflate(strm, Z_NO_FLUSH)` with `input` as next_in and `out` as next_out.
    /// Returns (bytes of input used, bytes written, status).
    pub(crate) fn inflate(&mut self, input: &[u8], out: &mut [u8]) -> (usize, usize, Status) {
        let mut next = 0usize;
        let mut put = 0usize;
        macro_rules! need {
            ($n:expr) => {
                while self.bits < $n {
                    if next >= input.len() {
                        break;
                    }
                    self.hold |= (input[next] as u64) << self.bits;
                    next += 1;
                    self.bits += 8;
                }
                if self.bits < $n {
                    return (next, put, Status::Ok);
                }
            };
        }
        macro_rules! pull {
            () => {
                if next >= input.len() {
                    return (next, put, Status::Ok);
                }
                self.hold |= (input[next] as u64) << self.bits;
                next += 1;
                self.bits += 8;
            };
        }
        macro_rules! take {
            ($n:expr) => {{
                let n: u32 = $n;
                let v = (self.hold & ((1u64 << n) - 1)) as usize;
                self.hold >>= n;
                self.bits -= n;
                v
            }};
        }
        loop {
            match self.state {
                State::Head => {
                    need!(16);
                    let h = self.hold & 0xffff;
                    if (((h & 0xff) << 8) + (h >> 8)) % 31 != 0 {
                        self.bad("incorrect header check");
                        continue;
                    }
                    if h & 0x0f != 8 {
                        self.bad("unknown compression method");
                        continue;
                    }
                    let len = ((h >> 4) & 0x0f) + 8;
                    if len > 15 {
                        self.bad("invalid window size");
                        continue;
                    }
                    let dict = h & 0x2000 != 0;
                    take!(16);
                    self.state = if dict { State::Dict } else { State::Type };
                }
                State::Dict => {
                    need!(32);
                    return (next, put, Status::NeedDict);
                }
                State::Type => {
                    if self.last {
                        let r = self.bits % 8;
                        take!(r);
                        self.state = if self.zlib { State::Check } else { State::Done };
                        continue;
                    }
                    need!(3);
                    self.last = take!(1) == 1;
                    match take!(2) {
                        0 => self.state = State::Stored,
                        1 => {
                            let mut l = [0u8; 288];
                            l[..144].fill(8);
                            l[144..256].fill(9);
                            l[256..280].fill(7);
                            l[280..].fill(8);
                            self.lcode = Some(Huffman::build(&l, Kind::Lens).expect("fixed"));
                            self.dcode =
                                Some(Huffman::build(&[5u8; 32], Kind::Dists).expect("fixed"));
                            self.state = State::Len;
                        }
                        2 => self.state = State::Table,
                        _ => self.bad("invalid block type"),
                    }
                }
                State::Stored => {
                    let r = self.bits % 8;
                    take!(r);
                    need!(32);
                    let h = self.hold & 0xffff_ffff;
                    if (h & 0xffff) != ((h >> 16) ^ 0xffff) {
                        self.bad("invalid stored block lengths");
                        continue;
                    }
                    self.length = (h & 0xffff) as usize;
                    take!(32);
                    self.state = State::Copy;
                }
                State::Copy => {
                    if self.length > 0 {
                        // Bits left in the hold are whole bytes here (the hold is byte
                        // aligned after the stored header); zlib keeps them in the hold too.
                        let mut copy = self.length;
                        let avail = input.len() - next + (self.bits / 8) as usize;
                        copy = copy.min(avail).min(out.len() - put);
                        if copy == 0 {
                            return (next, put, Status::Ok);
                        }
                        for _ in 0..copy {
                            let byte = if self.bits >= 8 {
                                take!(8) as u8
                            } else {
                                let b = input[next];
                                next += 1;
                                b
                            };
                            self.emit(out, &mut put, byte);
                        }
                        self.length -= copy;
                        continue;
                    }
                    self.state = State::Type;
                }
                State::Table => {
                    need!(14);
                    self.nlen = take!(5) + 257;
                    self.ndist = take!(5) + 1;
                    self.ncode = take!(4) + 4;
                    if self.nlen > 286 || self.ndist > 30 {
                        self.bad("too many length or distance symbols");
                        continue;
                    }
                    self.have = 0;
                    self.lens = [0; 320];
                    self.state = State::LenLens;
                }
                State::LenLens => {
                    while self.have < self.ncode {
                        need!(3);
                        self.lens[ORDER[self.have]] = take!(3) as u8;
                        self.have += 1;
                    }
                    while self.have < 19 {
                        self.lens[ORDER[self.have]] = 0;
                        self.have += 1;
                    }
                    match Huffman::build(&self.lens[..19], Kind::Codes) {
                        Ok(h) => self.codes = Some(h),
                        Err(()) => {
                            self.bad("invalid code lengths set");
                            continue;
                        }
                    }
                    self.have = 0;
                    self.state = State::CodeLens;
                }
                State::CodeLens => {
                    let total = self.nlen + self.ndist;
                    while self.have < total {
                        let codes = self.codes.as_ref().expect("code lengths code");
                        let (sym, len) = loop {
                            if codes.empty {
                                // zlib's empty table decodes every 1-bit pattern as 0.
                                if self.bits >= 1 {
                                    break (0u16, 1u32);
                                }
                            } else if let Decoded::Sym(s, l) = codes.decode(self.hold, self.bits) {
                                break (s, l);
                            }
                            pull!();
                        };
                        if sym < 16 {
                            take!(len);
                            self.lens[self.have] = sym as u8;
                            self.have += 1;
                            continue;
                        }
                        let (extra, base) = match sym {
                            16 => (2, 3),
                            17 => (3, 3),
                            _ => (7, 11),
                        };
                        need!(len + extra);
                        take!(len);
                        if sym == 16 && self.have == 0 {
                            self.bad("invalid bit length repeat");
                            break;
                        }
                        let rep = if sym == 16 {
                            self.lens[self.have - 1]
                        } else {
                            0
                        };
                        let copy = base + take!(extra);
                        if self.have + copy > total {
                            self.bad("invalid bit length repeat");
                            break;
                        }
                        for _ in 0..copy {
                            self.lens[self.have] = rep;
                            self.have += 1;
                        }
                    }
                    if self.state == State::Bad {
                        continue;
                    }
                    if self.lens[256] == 0 {
                        self.bad("invalid code -- missing end-of-block");
                        continue;
                    }
                    match Huffman::build(&self.lens[..self.nlen], Kind::Lens) {
                        Ok(h) => self.lcode = Some(h),
                        Err(()) => {
                            self.bad("invalid literal/lengths set");
                            continue;
                        }
                    }
                    match Huffman::build(&self.lens[self.nlen..total], Kind::Dists) {
                        Ok(h) => self.dcode = Some(h),
                        Err(()) => {
                            self.bad("invalid distances set");
                            continue;
                        }
                    }
                    self.state = State::Len;
                }
                State::Len => {
                    // The fast loop: literals while there is room and input.
                    let (sym, len) = loop {
                        let l = self.lcode.as_ref().expect("lit/len code");
                        match l.decode(self.hold, self.bits) {
                            Decoded::Sym(s, n) => break (s, n),
                            Decoded::Invalid(n) => break (u16::MAX, n),
                            Decoded::Need => {
                                pull!();
                            }
                        }
                    };
                    take!(len);
                    if sym == u16::MAX || sym >= 286 {
                        self.bad("invalid literal/length code");
                        continue;
                    }
                    if sym < 256 {
                        self.length = sym as usize;
                        self.state = State::Lit;
                    } else if sym == 256 {
                        self.state = State::Type;
                    } else {
                        let i = (sym - 257) as usize;
                        self.length = LBASE[i] as usize;
                        self.extra = LEXT[i] as u32;
                        self.state = State::LenExt;
                    }
                }
                State::Lit => {
                    if put >= out.len() {
                        return (next, put, Status::Ok);
                    }
                    let b = self.length as u8;
                    self.emit(out, &mut put, b);
                    self.state = State::Len;
                }
                State::LenExt => {
                    if self.extra > 0 {
                        need!(self.extra);
                        self.length += take!(self.extra);
                    }
                    self.state = State::Dist;
                }
                State::Dist => {
                    let (sym, len) = loop {
                        let d = self.dcode.as_ref().expect("distance code");
                        match d.decode(self.hold, self.bits) {
                            Decoded::Sym(s, n) => break (s, n),
                            Decoded::Invalid(n) => break (u16::MAX, n),
                            Decoded::Need => {
                                pull!();
                            }
                        }
                    };
                    take!(len);
                    if sym == u16::MAX || sym >= 30 {
                        self.bad("invalid distance code");
                        continue;
                    }
                    self.offset = DBASE[sym as usize] as usize;
                    self.extra = DEXT[sym as usize] as u32;
                    self.state = State::DistExt;
                }
                State::DistExt => {
                    if self.extra > 0 {
                        need!(self.extra);
                        self.offset += take!(self.extra);
                    }
                    self.state = State::Match;
                }
                State::Match => {
                    if put >= out.len() {
                        return (next, put, Status::Ok);
                    }
                    if self.offset as u64 > self.total {
                        self.bad("invalid distance too far back");
                        continue;
                    }
                    let n = self.length.min(out.len() - put);
                    for _ in 0..n {
                        let b = self.window[(self.wpos + WSIZE - self.offset) & (WSIZE - 1)];
                        self.emit(out, &mut put, b);
                    }
                    self.length -= n;
                    if self.length == 0 {
                        self.state = State::Len;
                    }
                }
                State::Check => {
                    need!(32);
                    let h = take!(32) as u32;
                    let want = h.swap_bytes();
                    if want != (self.b << 16) | self.a {
                        self.bad("incorrect data check");
                        continue;
                    }
                    self.state = State::Done;
                }
                State::Done => return (next, put, Status::StreamEnd),
                State::Bad => return (next, put, Status::DataError(self.msg)),
            }
        }
    }
}

/// Python's `zlib.decompressobj().decompress(data, max_length)`: the output, and whether
/// input was left unconsumed because the output reached `max_length`. Err is `zlib.error`.
pub(crate) fn decompress_limited(data: &[u8], max_length: usize) -> Result<(Vec<u8>, bool), ()> {
    let mut z = Inflate::new();
    let mut out = vec![0u8; max_length];
    let mut pos = 0;
    let mut written = 0;
    loop {
        let (used, n, st) = z.inflate(&data[pos..], &mut out[written..]);
        pos += used;
        written += n;
        match st {
            Status::DataError(_) | Status::NeedDict => return Err(()),
            Status::StreamEnd => {
                out.truncate(written);
                return Ok((out, false));
            }
            Status::Ok => {
                if written == max_length {
                    out.truncate(written);
                    return Ok((out, pos < data.len() || z.bits >= 8));
                }
                if used == 0 && n == 0 {
                    out.truncate(written);
                    return Ok((out, false));
                }
            }
        }
    }
}
