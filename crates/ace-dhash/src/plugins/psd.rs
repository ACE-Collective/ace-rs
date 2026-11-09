//! PsdImagePlugin, approximated: the header is checked; the image is not decoded.

use crate::Raise;
use crate::io::{u16be, u32be};
use crate::open::{NoDecoder, Opened};

pub(crate) fn accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"8BPS"))
}

pub(crate) fn open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let s = d.get(..26).ok_or_else(Raise::struct_error)?;
    if u16be(s, 4)? != 1 {
        return Err(Raise::syntax("not a PSD file"));
    }
    let channels = u16be(s, 12)?;
    let size = (u32be(s, 18)? as i64, u32be(s, 14)? as i64);
    let bits = u16be(s, 22)?;
    let pmode = u16be(s, 24)?;
    let mode = match (pmode, bits) {
        (0, 1) => "1",
        (0, 8) | (1, 8) | (8, 8) => "L",
        (2, 8) => "P",
        (3, 8) => "RGB",
        (4, 8) => "CMYK",
        (7, 8) => "L",
        (9, 8) => "LAB",
        _ => return Err(Raise::os("not enough information about this PSD mode")),
    };
    if channels > 56 {
        return Err(Raise::value("Channels > 56 are not supported"));
    }
    Ok(Opened::new("PSD", mode, size, Box::new(NoDecoder("PSD"))))
}
