//! DdsImagePlugin, approximated: the 124-byte header is checked; nothing is decoded.

use crate::Raise;
use crate::io::u32le;
use crate::open::{NoDecoder, Opened};

pub(crate) fn accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"DDS "))
}

pub(crate) fn open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let hs = u32le(d, 4)?;
    if hs != 124 {
        return Err(Raise::os("Unsupported header size"));
    }
    if d.len() < 128 {
        return Err(Raise::os("Truncated DDS file"));
    }
    let size = (u32le(d, 16)? as i64, u32le(d, 12)? as i64);
    Ok(Opened::new("DDS", "RGBA", size, Box::new(NoDecoder("DDS"))))
}
