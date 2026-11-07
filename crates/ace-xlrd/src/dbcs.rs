//! Python's multi byte codecs a codepage can name. encoding_rs holds the tables; the data in
//! `tables.rs` is where Python's differ, checked over every byte pair.

use crate::py::{R, decode_error};
use crate::tables::{CP950_CHANGED, CP950_UNDEFINED, GBK_UNDEFINED, JOHAB_EXCEPTIONS};

#[derive(Clone, Copy)]
pub(crate) enum Double {
    Cp932,
    Gbk,
    Cp949,
    Cp950,
    Johab,
}

impl Double {
    fn name(self) -> &'static str {
        match self {
            Double::Cp932 => "cp932",
            Double::Gbk => "gbk",
            Double::Cp949 => "cp949",
            Double::Cp950 => "cp950",
            Double::Johab => "johab",
        }
    }
}

fn in_runs(runs: &[(u16, u16)], k: u16) -> bool {
    let i = runs.partition_point(|r| r.1 < k);
    runs.get(i).is_some_and(|r| r.0 <= k)
}

/// A byte that stands alone in the codec, past ASCII.
fn single(kind: Double, b: u8) -> Option<char> {
    match (kind, b) {
        (Double::Cp932, 0x80) => Some('\u{80}'),
        (Double::Cp932, 0xa0) => Some('\u{f8f0}'),
        (Double::Cp932, 0xfd) => Some('\u{f8f1}'),
        (Double::Cp932, 0xfe) => Some('\u{f8f2}'),
        (Double::Cp932, 0xff) => Some('\u{f8f3}'),
        (Double::Cp932, 0xa1..=0xdf) => char::from_u32(0xff61 + u32::from(b) - 0xa1),
        _ => None,
    }
}

fn via(enc: &'static encoding_rs::Encoding, a: u8, b: u8) -> Option<String> {
    enc.decode_without_bom_handling_and_without_replacement(&[a, b])
        .map(|c| c.into_owned())
}

/// The rule for Johab: Hangul by its 5-5-5 bit fields, the rest as rows of KS X 1001.
fn johab(a: u8, b: u8) -> Option<String> {
    let k = u16::from(a) << 8 | u16::from(b);
    if let Ok(i) = JOHAB_EXCEPTIONS.binary_search_by_key(&k, |e| e.0) {
        let c = JOHAB_EXCEPTIONS.get(i)?.1;
        return char::from_u32(u32::from(c))
            .filter(|_| c != 0xffff)
            .map(String::from);
    }
    if a <= 0xd3 {
        let i = u32::from((k >> 10) & 31);
        let j = match (k >> 5) & 31 {
            v @ 3..=7 => v - 3,
            v @ 10..=15 => v - 5,
            v @ 18..=23 => v - 7,
            v @ 26..=29 => v - 9,
            _ => return None,
        };
        let t = match k & 31 {
            v @ 1..=17 => v - 1,
            v @ 19..=29 => v - 2,
            _ => return None,
        };
        if !(2..=20).contains(&i) {
            return None;
        }
        return char::from_u32(0xac00 + ((i - 2) * 21 + u32::from(j)) * 28 + u32::from(t))
            .map(String::from);
    }
    let mut c = match a {
        0xd9..=0xde => (a - 0xd9) * 2 + 0xa1,
        0xe0..=0xf9 => (a - 0xe0) * 2 + 0xca,
        _ => return None,
    };
    let d = match b {
        0x31..=0x7e => b - 0x31 + 0xa1,
        0x91..=0xa0 => b - 0x91 + 0xa1 + 0x4e,
        0xa1..=0xfe => {
            c += 1;
            b
        }
        _ => return None,
    };
    via(encoding_rs::EUC_KR, c, d)
}

fn pair(kind: Double, a: u8, b: u8) -> Option<String> {
    let k = u16::from(a) << 8 | u16::from(b);
    match kind {
        Double::Cp932 => via(encoding_rs::SHIFT_JIS, a, b),
        Double::Cp949 => via(encoding_rs::EUC_KR, a, b),
        Double::Gbk => {
            if a == 0x80 || in_runs(GBK_UNDEFINED, k) {
                return None;
            }
            via(encoding_rs::GBK, a, b)
        }
        Double::Cp950 => {
            let i = CP950_CHANGED.partition_point(|r| r.1 < k);
            if let Some(r) = CP950_CHANGED.get(i)
                && r.0 <= k
            {
                return char::from_u32(r.2 + u32::from(k - r.0)).map(String::from);
            }
            if in_runs(CP950_UNDEFINED, k) {
                return None;
            }
            via(encoding_rs::BIG5, a, b)
        }
        Double::Johab => johab(a, b),
    }
}

/// `bytes.decode(codec)`.
pub(crate) fn decode(kind: Double, d: &[u8]) -> R<String> {
    let name = kind.name();
    let mut s = String::with_capacity(d.len());
    let mut i = 0;
    while let Some(&b) = d.get(i) {
        if b < 0x80 {
            s.push(b as char);
            i += 1;
            continue;
        }
        if let Some(c) = single(kind, b) {
            s.push(c);
            i += 1;
            continue;
        }
        let Some(&t) = d.get(i + 1) else {
            return Err(decode_error(
                name,
                d,
                i,
                i + 1,
                "incomplete multibyte sequence",
            ));
        };
        match pair(kind, b, t) {
            Some(u) => s.push_str(&u),
            None => {
                return Err(decode_error(
                    name,
                    d,
                    i,
                    i + 1,
                    "illegal multibyte sequence",
                ));
            }
        }
        i += 2;
    }
    Ok(s)
}
