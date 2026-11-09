//! IcnsImagePlugin, approximated: the block list is read for its largest size; the icons are
//! not decoded.

use crate::Raise;
use crate::io::u32be;
use crate::open::{NoDecoder, Opened};

pub(crate) fn accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"icns"))
}

fn icon_size(t: &[u8]) -> Option<i64> {
    Some(match t {
        b"ic10" => 1024,
        b"ic09" | b"ic14" => 512,
        b"ic08" | b"ic13" => 256,
        b"ic07" | b"ic12" => 128,
        b"it32" | b"ic11" => 64,
        b"ih32" => 48,
        b"icp6" => 64,
        b"il32" | b"icp5" => 32,
        b"is32" | b"icp4" => 16,
        _ => return None,
    })
}

pub(crate) fn open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let total = u32be(d, 4)? as usize;
    let mut pos = 8;
    let mut best = 0;
    while pos < total.min(d.len()) {
        let t = d
            .get(pos..pos + 4)
            .ok_or_else(|| Raise::syntax("invalid block header"))?;
        let n = u32be(d, pos + 4)? as usize;
        if n == 0 {
            return Err(Raise::syntax("invalid block header"));
        }
        if let Some(s) = icon_size(t) {
            best = best.max(s);
        }
        pos += n;
    }
    if best == 0 {
        return Err(Raise::syntax("No icons found"));
    }
    Ok(Opened::new(
        "ICNS",
        "RGBA",
        (best, best),
        Box::new(NoDecoder("ICNS")),
    ))
}
