//! The stub plugins (BUFR, GRIB, HDF5, WMF): Pillow identifies them but, with no handler
//! installed, `load` raises OSError("cannot find loader for this ... file").

use crate::Raise;
use crate::io::{u16le, u32le};
use crate::open::{Fails, Opened};

fn stub<'a>(format: &'static str, mode: &'static str, size: (i64, i64)) -> Opened<'a> {
    let mut o = Opened::new(
        format,
        mode,
        size,
        Box::new(Fails(Raise::os(format!(
            "cannot find loader for this {format} file"
        )))),
    );
    o.stub = true;
    o
}

pub(crate) fn bufr_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"BUFR") || p.starts_with(b"ZCZC"))
}

pub(crate) fn bufr_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    if !bufr_accept(&d[..d.len().min(4)])? {
        return Err(Raise::syntax("Not a BUFR file"));
    }
    Ok(stub("BUFR", "F", (0, 0)))
}

pub(crate) fn grib_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.len() >= 8 && p.starts_with(b"GRIB") && p[7] == 1)
}

pub(crate) fn grib_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    if !grib_accept(&d[..d.len().min(8)])? {
        return Err(Raise::syntax("Not a GRIB file"));
    }
    Ok(stub("GRIB", "F", (0, 0)))
}

pub(crate) fn hdf5_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"\x89HDF\r\n\x1a\n"))
}

pub(crate) fn hdf5_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    if !hdf5_accept(&d[..d.len().min(8)])? {
        return Err(Raise::syntax("Not an HDF file"));
    }
    Ok(stub("HDF5", "F", (0, 0)))
}

pub(crate) fn wmf_accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"\xd7\xcd\xc6\x9a\x00\x00") || p.starts_with(b"\x01\x00\x00\x00"))
}

fn si16(s: &[u8], o: usize) -> Result<i64, Raise> {
    Ok(u16le(s, o)? as i16 as i64)
}

fn si32(s: &[u8], o: usize) -> Result<i64, Raise> {
    Ok(u32le(s, o)? as i32 as i64)
}

pub(crate) fn wmf_open(d: &[u8]) -> Result<Opened<'_>, Raise> {
    let s = &d[..d.len().min(44)];
    let size;
    if s.starts_with(b"\xd7\xcd\xc6\x9a\x00\x00") {
        let inch = u16le(s, 14)? as i64;
        if inch == 0 {
            return Err(Raise::value("Invalid inch"));
        }
        let (x0, y0, x1, y1) = (si16(s, 6)?, si16(s, 8)?, si16(s, 10)?, si16(s, 12)?);
        size = (
            ((x1 - x0) * 72).div_euclid(inch),
            ((y1 - y0) * 72).div_euclid(inch),
        );
        if s.get(22..26) != Some(b"\x01\x00\t\x00") {
            return Err(Raise::syntax("Unsupported WMF file format"));
        }
    } else if s.starts_with(b"\x01\x00\x00\x00") && s.get(40..44) == Some(b" EMF") {
        let (x0, y0, x1, y1) = (si32(s, 8)?, si32(s, 12)?, si32(s, 16)?, si32(s, 20)?);
        let frame = (si32(s, 24)?, si32(s, 28)?, si32(s, 32)?, si32(s, 36)?);
        if frame.2 == frame.0 || frame.3 == frame.1 {
            return Err(Raise::new(
                crate::Kind::ZeroDivisionError,
                "float division by zero",
            ));
        }
        size = (x1 - x0, y1 - y0);
    } else {
        return Err(Raise::syntax("Unsupported file format"));
    }
    Ok(stub("WMF", "RGB", size))
}
