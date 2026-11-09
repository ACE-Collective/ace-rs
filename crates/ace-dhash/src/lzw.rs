//! libtiff 4.7.2's LZW decoder (tif_lzw.c, new-style codes), PackBits (tif_packbits.c) and
//! Deflate (tif_zip.c over zlib) strip decoders: each fills exactly `out` or fails.

use crate::inflate::{Inflate, Status};

const CODE_CLEAR: usize = 256;
const CODE_EOI: usize = 257;
const CODE_FIRST: usize = 258;
const CSIZE: usize = 4096;

#[derive(Clone, Copy, Default)]
struct Code {
    next: Option<u16>,
    length: u16,
    value: u8,
    firstchar: u8,
}

/// LZWDecode for one strip: Err on a code not yet in the table, a stream that ends without
/// filling `out`, or old-style (bit-reversed) codes, which this port does not decode.
pub(crate) fn tiff_lzw(data: &[u8], out: &mut [u8]) -> Result<(), &'static str> {
    if data.len() >= 2 && data[0] == 0 && data[1] & 1 != 0 {
        return Err("old-style LZW");
    }
    let mut tab = vec![Code::default(); CSIZE];
    for (i, c) in tab.iter_mut().enumerate().take(256) {
        *c = Code {
            next: None,
            length: 1,
            value: i as u8,
            firstchar: i as u8,
        };
    }
    let mut bitpos: u64 = 0;
    let total_bits = data.len() as u64 * 8;
    let mut nbits = 9u32;
    // free_ent: None is "before the table" (dec_codetab - 1)
    let mut free_ent: Option<usize> = None;
    let mut maxcode = (1usize << 9) - 2;
    let mut oldcode = 0usize;
    let mut op = 0usize;
    let occ_total = out.len();
    if occ_total == 0 {
        return Ok(());
    }
    let next_code = |bitpos: &mut u64, nbits: u32| -> Option<usize> {
        if *bitpos + nbits as u64 > total_bits {
            return None;
        }
        let mut v = 0usize;
        for _ in 0..nbits {
            let byte = data[(*bitpos / 8) as usize];
            let bit = (byte >> (7 - (*bitpos % 8))) & 1;
            v = (v << 1) | bit as usize;
            *bitpos += 1;
        }
        Some(v)
    };
    let write = |tab: &[Code], code: usize, out: &mut [u8], op: &mut usize| {
        let len = tab[code].length as usize;
        let n = len.min(out.len() - *op);
        // the string ends at op + len; only the part that fits is written
        let mut c = Some(code as u16);
        let mut pos = len;
        while let Some(ci) = c {
            pos -= 1;
            if pos < n {
                out[*op + pos] = tab[ci as usize].value;
            }
            c = tab[ci as usize].next;
            if pos == 0 {
                break;
            }
        }
        *op += n;
    };
    loop {
        let Some(code) = next_code(&mut bitpos, nbits) else {
            return Err("not terminated with EOI code");
        };
        if code == CODE_EOI {
            break;
        }
        if code == CODE_CLEAR {
            free_ent = Some(CODE_FIRST);
            nbits = 9;
            maxcode = (1 << 9) - 2;
            let mut c;
            loop {
                c = next_code(&mut bitpos, nbits).ok_or("not terminated with EOI code")?;
                if c != CODE_CLEAR {
                    break;
                }
            }
            if c == CODE_EOI {
                break;
            }
            if c > CODE_EOI {
                return Err("Using code not yet in table");
            }
            out[op] = c as u8;
            op += 1;
            oldcode = c;
            if op == occ_total {
                break;
            }
            continue;
        }
        let fe = free_ent;
        if code < 256 {
            if fe.is_none_or(|f| code > f) {
                return Err("Using code not yet in table");
            }
        } else if fe.is_none_or(|f| code > f) {
            return Err("Using code not yet in table");
        }
        let f = fe.expect("free entry");
        let value = if code >= CODE_FIRST {
            if code == f {
                tab[oldcode].firstchar
            } else {
                tab[code].firstchar
            }
        } else {
            code as u8
        };
        tab[f] = Code {
            next: Some(oldcode as u16),
            length: tab[oldcode].length + 1,
            value,
            firstchar: tab[oldcode].firstchar,
        };
        let mut nf = f + 1;
        if nf > maxcode {
            nbits = (nbits + 1).min(12);
            maxcode = (1usize << nbits) - 2;
            if nf >= CSIZE {
                free_ent = None;
                nf = usize::MAX;
            }
        }
        if nf != usize::MAX {
            free_ent = Some(nf);
        }
        oldcode = code;
        if code < 256 {
            out[op] = code as u8;
            op += 1;
        } else {
            write(&tab, code, out, &mut op);
        }
        if op == occ_total {
            break;
        }
    }
    if op < occ_total {
        return Err("Not enough data");
    }
    Ok(())
}

/// PackBitsDecode.
pub(crate) fn packbits(data: &[u8], out: &mut [u8]) -> Result<(), &'static str> {
    let mut bp = 0usize;
    let mut op = 0usize;
    let mut occ = out.len();
    while bp < data.len() && occ > 0 {
        let n = data[bp] as i8 as i64;
        bp += 1;
        if n < 0 {
            if n == -128 {
                continue;
            }
            let mut n = (-n + 1) as usize;
            if occ < n {
                n = occ;
            }
            if bp >= data.len() {
                break;
            }
            occ -= n;
            let b = data[bp];
            bp += 1;
            out[op..op + n].fill(b);
            op += n;
        } else {
            let mut n = n as usize;
            if occ < n + 1 {
                n = occ - 1;
            }
            if data.len() - bp < n + 1 {
                break;
            }
            let n = n + 1;
            out[op..op + n].copy_from_slice(&data[bp..bp + n]);
            op += n;
            occ -= n;
            bp += n;
        }
    }
    if occ > 0 {
        return Err("Not enough data for scanline");
    }
    Ok(())
}

/// ZIPDecode with zlib: inflate(Z_PARTIAL_FLUSH) over the whole strip.
pub(crate) fn deflate(data: &[u8], out: &mut [u8]) -> Result<(), &'static str> {
    let mut z = Inflate::new();
    let mut pos = 0;
    let mut op = 0;
    loop {
        let (used, n, st) = z.inflate(&data[pos..], &mut out[op..]);
        pos += used;
        op += n;
        match st {
            Status::StreamEnd => break,
            Status::DataError(_) => return Err("Decoding error"),
            Status::NeedDict => return Err("ZLib error"),
            Status::Ok => {
                if op == out.len() {
                    break;
                }
                if used == 0 && n == 0 {
                    return Err("ZLib error");
                }
            }
        }
    }
    if op != out.len() {
        return Err("Not enough data");
    }
    Ok(())
}
