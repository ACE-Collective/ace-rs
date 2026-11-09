//! Jpeg2KImagePlugin, approximated: the SIZ marker of a codestream, or the ihdr box of a JP2
//! file, gives the size and mode; nothing is decoded (Pillow uses OpenJPEG).

use crate::Raise;
use crate::io::{u16be, u32be};
use crate::open::{NoDecoder, Opened};

pub(crate) fn accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(
        p.starts_with(b"\xff\x4f\xff\x51")
            || p.starts_with(b"\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a"),
    )
}

fn mode(c: u16) -> Result<&'static str, Raise> {
    Ok(match c {
        1 => "L",
        2 => "LA",
        3 => "RGB",
        4 => "RGBA",
        _ => return Err(Raise::syntax("unable to determine J2K image mode")),
    })
}

pub(crate) fn open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    if d.starts_with(b"\xff\x4f\xff\x51") {
        let s = d.get(6..).ok_or_else(Raise::struct_error)?;
        let (xs, ys) = (u32be(s, 2)?, u32be(s, 6)?);
        let (xo, yo) = (u32be(s, 10)?, u32be(s, 14)?);
        let c = u16be(s, 34)?;
        let size = (xs as i64 - xo as i64, ys as i64 - yo as i64);
        return Ok(Opened::new(
            "JPEG2000",
            mode(c)?,
            size,
            Box::new(NoDecoder("JPEG 2000")),
        ));
    }
    let pos = d
        .windows(4)
        .position(|w| w == b"ihdr")
        .ok_or_else(|| Raise::syntax("could not find JP2 header"))?;
    let s = &d[pos + 4..];
    let (h, w, c) = (u32be(s, 0)?, u32be(s, 4)?, u16be(s, 8)?);
    Ok(Opened::new(
        "JPEG2000",
        mode(c)?,
        (w as i64, h as i64),
        Box::new(NoDecoder("JPEG 2000")),
    ))
}
