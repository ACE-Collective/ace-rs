//! Pillow's "raw" decoder (RawDecode.c) and the tile loop of `ImageFile.load` around it.

use crate::Raise;
use crate::image::Canvas;
use crate::unpack::Unpacker;

/// A "raw" tile: extents, file offset, unpacker, stride (0 for none) and orientation.
#[derive(Clone, Copy)]
pub(crate) struct RawTile {
    pub(crate) x0: usize,
    pub(crate) y0: usize,
    pub(crate) x1: usize,
    pub(crate) y1: usize,
    pub(crate) offset: usize,
    pub(crate) u: Unpacker,
    pub(crate) stride: usize,
    pub(crate) bottom_up: bool,
}

/// Checks extents as `decoder.setimage` does.
pub(crate) fn check_extents(c: &Canvas, x0: i64, y0: i64, x1: i64, y1: i64) -> Result<(), Raise> {
    if x0 < 0 || y0 < 0 || x1 <= x0 || y1 <= y0 || x1 > c.w as i64 || y1 > c.h as i64 {
        return Err(Raise::value("tile cannot extend outside image"));
    }
    Ok(())
}

/// Decodes one raw tile from `data` (the bytes from the tile's offset on). Ok(true) when the
/// decoder finished, Ok(false) when it ran out of data (the caller raises "image file is
/// truncated", or "not enough image data" for `set_as_raw`).
pub(crate) fn decode(c: &mut Canvas, data: &[u8], t: &RawTile) -> Result<bool, Raise> {
    let xsize = t.x1 - t.x0;
    let ysize = t.y1 - t.y0;
    let bytes = t.u.row_bytes(xsize);
    let skip = if t.stride != 0 {
        if t.stride < bytes {
            return Err(Raise::decoder(-8));
        }
        t.stride - bytes
    } else {
        0
    };
    let mut pos = 0usize;
    for i in 0..ysize {
        if i > 0 {
            pos += skip;
        }
        if data.len() < pos || data.len() - pos < bytes {
            return Ok(false);
        }
        let y = if t.bottom_up { ysize - 1 - i } else { i };
        c.unpack_row(&t.u, t.x0, t.y0 + y, &data[pos..pos + bytes], xsize);
        pos += bytes;
    }
    Ok(true)
}

/// `ImageFile.load` over raw tiles: sorted by offset, each decoded from its offset.
pub(crate) fn load_tiles(c: &mut Canvas, data: &[u8], tiles: &mut [RawTile]) -> Result<(), Raise> {
    tiles.sort_by_key(|t| t.offset);
    for t in tiles.iter() {
        check_extents(c, t.x0 as i64, t.y0 as i64, t.x1 as i64, t.y1 as i64)?;
        let rest = data.get(t.offset..).unwrap_or(&[]);
        if !decode(c, rest, t)? {
            return Err(Raise::truncated());
        }
    }
    Ok(())
}

/// `PyDecoder.set_as_raw(data, rawmode, (stride, ystep))` over the whole image.
pub(crate) fn set_as_raw(
    c: &mut Canvas,
    data: &[u8],
    u: Unpacker,
    stride: usize,
    bottom_up: bool,
) -> Result<(), Raise> {
    let t = RawTile {
        x0: 0,
        y0: 0,
        x1: c.w,
        y1: c.h,
        offset: 0,
        u,
        stride,
        bottom_up,
    };
    if !decode(c, data, &t)? {
        return Err(Raise::value("not enough image data"));
    }
    Ok(())
}
