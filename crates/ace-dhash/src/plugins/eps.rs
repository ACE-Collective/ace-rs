//! EpsImagePlugin, approximated: Pillow needs a %%BoundingBox in the header; loading runs
//! Ghostscript, which this crate does not.

use crate::Raise;
use crate::io::u32le;
use crate::open::{NoDecoder, Opened};

pub(crate) fn accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"%!PS") || (p.len() >= 4 && u32le(p, 0)? == 0xC6D3D0C5))
}

pub(crate) fn open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let (start, len) = if d.starts_with(b"%!PS") {
        (0, d.len())
    } else {
        ((u32le(d, 4)? as usize).min(d.len()), u32le(d, 8)? as usize)
    };
    let body = &d[start..(start.saturating_add(len)).min(d.len())];
    for line in body.split(|&c| c == b'\n' || c == b'\r') {
        if let Some(rest) = line.strip_prefix(b"%%BoundingBox:") {
            let v: Vec<f64> = String::from_utf8_lossy(rest)
                .split_whitespace()
                .filter_map(|t| t.parse().ok())
                .collect();
            if v.len() == 4 {
                let size = ((v[2] - v[0]).ceil() as i64, (v[3] - v[1]).ceil() as i64);
                return Ok(Opened::new(
                    "EPS",
                    "RGB",
                    size,
                    Box::new(NoDecoder("EPS (Ghostscript)")),
                ));
            }
        }
        if line.starts_with(b"%%EndComments") {
            break;
        }
    }
    Err(Raise::os("cannot determine EPS bounding box"))
}
