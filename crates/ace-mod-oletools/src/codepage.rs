//! oletools' `codepage2codec`, and Python's decoders with `errors='replace'`. The single-byte and
//! double-byte tables are Python's own, from tools/oletools/make-codepages.

use std::io::Read;
use std::sync::OnceLock;

use flate2::read::ZlibDecoder;

include!("codepage_tables.rs");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Single,
    Multi,
    Special,
}

#[derive(Debug)]
pub(crate) struct Codec {
    name: &'static str,
    kind: Kind,
    offset: usize,
}

fn tables() -> &'static [u16] {
    static TABLES: OnceLock<Vec<u16>> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut bytes = Vec::new();
        ZlibDecoder::new(&include_bytes!("codepage_tables.bin")[..])
            .read_to_end(&mut bytes)
            .expect("the tables decompress");
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect()
    })
}

const LEAD: u16 = 0xFFFE;
const INVALID: u16 = 0xFFFD;

/// A code page's decoder.
#[derive(Debug, Clone, Copy)]
pub struct Decoder(&'static Codec);

impl Decoder {
    /// `codepage2codec`. A page Python has no codec for is UTF-8.
    pub fn for_codepage(page: u16) -> Decoder {
        PAGES.binary_search_by_key(&page, |row| row.0).map_or_else(
            |_| Decoder::named("utf-8"),
            |at| Decoder(&CODECS[PAGES[at].1 as usize]),
        )
    }

    pub fn latin1() -> Decoder {
        Decoder::named("iso8859-1")
    }

    pub fn cp1252() -> Decoder {
        Decoder::named("cp1252")
    }

    fn named(name: &str) -> Decoder {
        Decoder(
            CODECS
                .iter()
                .find(|codec| codec.name == name)
                .expect("a known codec"),
        )
    }

    pub fn name(&self) -> &'static str {
        self.0.name
    }

    /// `bytes.decode(codec, errors='replace')`.
    pub fn decode(&self, bytes: &[u8]) -> String {
        match self.0.kind {
            Kind::Single => {
                let table = &tables()[self.0.offset / 2..self.0.offset / 2 + 256];
                bytes
                    .iter()
                    .map(|&byte| to_char(table[byte as usize]))
                    .collect()
            }
            Kind::Multi => decode_multi(self.0.offset / 2, bytes),
            Kind::Special => match self.0.name {
                "utf-8" => String::from_utf8_lossy(bytes).into_owned(),
                "utf-16-le" => crate::py::decode_utf16le(bytes),
                "utf-16-be" => {
                    let swapped: Vec<u8> = bytes
                        .chunks(2)
                        .flat_map(|pair| {
                            if pair.len() == 2 {
                                vec![pair[1], pair[0]]
                            } else {
                                pair.to_vec()
                            }
                        })
                        .collect();
                    crate::py::decode_utf16le(&swapped)
                }
                "utf-32-le" => decode_utf32(bytes, u32::from_le_bytes),
                "utf-32-be" => decode_utf32(bytes, u32::from_be_bytes),
                _ => decode_utf7(bytes),
            },
        }
    }
}

fn to_char(unit: u16) -> char {
    char::from_u32(u32::from(unit)).unwrap_or(char::REPLACEMENT_CHARACTER)
}

fn decode_multi(offset: usize, bytes: &[u8]) -> String {
    let tables = tables();
    let singles = &tables[offset..offset + 256];
    // the pair tables follow, one for each lead byte in order
    let mut lead_tables = [0usize; 256];
    let mut next = offset + 256;
    for lead in 0..256 {
        if singles[lead] == LEAD {
            lead_tables[lead] = next;
            next += 256;
        }
    }
    let mut out = String::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let lead = bytes[at] as usize;
        let single = singles[lead];
        if single != LEAD {
            out.push(if single == INVALID {
                char::REPLACEMENT_CHARACTER
            } else {
                to_char(single)
            });
            at += 1;
            continue;
        }
        let Some(&trail) = bytes.get(at + 1) else {
            out.push(char::REPLACEMENT_CHARACTER);
            break;
        };
        match tables[lead_tables[lead] + trail as usize] {
            0xFFFF => {
                out.push(char::REPLACEMENT_CHARACTER);
                at += 1;
            }
            0xFFFE => {
                out.push(char::REPLACEMENT_CHARACTER);
                at += 2;
            }
            unit => {
                out.push(to_char(unit));
                at += 2;
            }
        }
    }
    out
}

fn decode_utf32(bytes: &[u8], read: fn([u8; 4]) -> u32) -> String {
    let mut out = String::with_capacity(bytes.len() / 4);
    for four in bytes.chunks(4) {
        match <[u8; 4]>::try_from(four)
            .ok()
            .map(read)
            .and_then(char::from_u32)
        {
            Some(c) => out.push(c),
            None => out.push(char::REPLACEMENT_CHARACTER),
        }
    }
    out
}

/// CPython's `PyUnicode_DecodeUTF7Stateful` with 'replace'.
fn decode_utf7(bytes: &[u8]) -> String {
    fn b64(byte: u8) -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some(u32::from(byte - b'A')),
            b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut units: Vec<u32> = Vec::with_capacity(bytes.len());
    let mut in_shift = false;
    let mut bits: u64 = 0;
    let mut count = 0u32;
    let mut pending: Option<u32> = None;
    let mut at = 0;
    let flush_units = |units: &mut Vec<u32>, pending: &mut Option<u32>| {
        if let Some(high) = pending.take() {
            units.push(high);
        }
    };
    while at < bytes.len() {
        let byte = bytes[at];
        if in_shift {
            if let Some(value) = b64(byte) {
                bits = (bits << 6) | u64::from(value);
                count += 6;
                at += 1;
                if count >= 16 {
                    let unit = ((bits >> (count - 16)) & 0xFFFF) as u32;
                    count -= 16;
                    bits &= (1u64 << count) - 1;
                    if let Some(high) = pending.take() {
                        if (0xDC00..=0xDFFF).contains(&unit) {
                            units.push(0x10000 + ((high - 0xD800) << 10) + (unit - 0xDC00));
                            continue;
                        }
                        units.push(high);
                    }
                    if (0xD800..=0xDBFF).contains(&unit) {
                        pending = Some(unit);
                    } else {
                        units.push(unit);
                    }
                }
            } else {
                in_shift = false;
                let bad = count >= 6 || (count > 0 && bits != 0);
                flush_units(&mut units, &mut pending);
                if bad {
                    // the partial character, which Python replaces, with its terminator left alone
                    units.push(0xFFFD);
                    if byte == b'-' {
                        at += 1;
                    }
                    continue;
                }
                if byte == b'-' {
                    at += 1;
                }
            }
        } else if byte == b'+' {
            at += 1;
            if bytes.get(at) == Some(&b'-') {
                at += 1;
                units.push(u32::from(b'+'));
            } else if bytes.get(at).copied().and_then(b64).is_some() {
                in_shift = true;
                bits = 0;
                count = 0;
            } else {
                units.push(0xFFFD);
                at += 1;
            }
        } else if byte < 0x80 {
            units.push(u32::from(byte));
            at += 1;
        } else {
            units.push(0xFFFD);
            at += 1;
        }
    }
    if in_shift {
        flush_units(&mut units, &mut pending);
        if count >= 6 || (count > 0 && bits != 0) {
            units.push(0xFFFD);
        }
    }
    units
        .into_iter()
        .map(|unit| char::from_u32(unit).unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}
