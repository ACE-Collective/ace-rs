//! AvifImagePlugin, approximated: libavif's parse is not ported. A file whose top-level ISO
//! BMFF boxes are well formed and include "meta" (or "moov"), ending at the end of the file, opens; nothing is decoded.

use crate::Raise;
use crate::io::u32be;
use crate::open::{NoDecoder, Opened};

pub(crate) fn accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.get(4..8) == Some(b"ftyp")
        && matches!(p.get(8..12), Some(b"avif" | b"avis" | b"mif1" | b"msf1")))
}

pub(crate) fn open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let mut pos = 0usize;
    let mut found = false;
    while pos + 8 <= d.len() {
        let size = u32be(d, pos)? as usize;
        let kind = &d[pos + 4..pos + 8];
        if kind == b"meta" || kind == b"moov" {
            found = true;
        }
        if size < 8 || pos + size > d.len() {
            return Err(Raise::syntax("Failed to decode image"));
        }
        pos += size;
    }
    if !found || pos != d.len() {
        return Err(Raise::syntax("Failed to decode image"));
    }
    Ok(Opened::new(
        "AVIF",
        "RGB",
        (1, 1),
        Box::new(NoDecoder("AVIF")),
    ))
}
