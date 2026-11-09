//! FpxImagePlugin and MicImagePlugin, approximated: both need olefile to find FlashPix or
//! Microsoft Image Composer streams, which is not ported. OLE files (Office documents and
//! the like) are taken as neither, which is Pillow's answer for them.

use crate::Raise;
use crate::open::Opened;

pub(crate) fn accept(p: &[u8]) -> Result<bool, Raise> {
    Ok(p.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"))
}

pub(crate) fn fpx_open(_d: &[u8]) -> Result<Opened<'_>, Raise> {
    Err(Raise::syntax("not an FPX file; invalid CLSID"))
}

pub(crate) fn mic_open(_d: &[u8]) -> Result<Opened<'_>, Raise> {
    Err(Raise::syntax("not an MIC file; no image entries"))
}
