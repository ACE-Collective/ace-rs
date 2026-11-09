//! A port of ace3's `dhash` module (`saq/modules/dhash.py`) and the parts of Pillow 13.0.0 it
//! uses: `is_image` (whether `Image.open` succeeds), `_image_hash` (the 512-bit row and column
//! difference hash of an image), and the similarity score.
//!
//! `Image.open` tries every registered plugin in turn, in the order a long-running ace3 process
//! has them once Pillow's `init()` has run (BMP, DIB, GIF, JPEG, PPM, PNG, then the rest by
//! plugin name). Each plugin's accept check and `_open` are ported, with Pillow's rule for which
//! exceptions move on to the next plugin (SyntaxError, IndexError, TypeError, struct.error, and,
//! inside `_open`, KeyError and EOFError) and which end the open.
//!
//! `_image_hash` decodes the image as Pillow does, pastes "RGBA" and "LA" images over white,
//! converts to "L" with Pillow's integer formulas, and resizes to 17x17 with Pillow's LANCZOS
//! resampler (`Resample.c`, fixed point). See [`image_hash`] for the formats it decodes and
//! where it departs from Pillow.

// The decoders are ports of C loops and keep their shape, index arithmetic included.
#![allow(
    clippy::needless_range_loop,
    clippy::collapsible_if,
    clippy::manual_range_contains,
    clippy::manual_is_multiple_of,
    clippy::explicit_counter_loop,
    clippy::if_same_then_else,
    clippy::chunks_exact_to_as_chunks
)]

mod hash;
mod image;
mod inflate;
mod io;
mod jpeg;
mod lzw;
mod open;
mod plugins;
mod pyparse;
mod resample;
mod unpack;

pub use hash::{format_percent, percent_similar, score_json};

/// Pillow's `MAX_IMAGE_PIXELS`: `int(1024 * 1024 * 1024 // 4 // 3)`.
pub const MAX_IMAGE_PIXELS: u64 = 1024 * 1024 * 1024 / 4 / 3;

/// The largest image this crate decodes: Pillow refuses to open more than twice
/// `MAX_IMAGE_PIXELS` (`DecompressionBombError`), so nothing larger reaches a decoder.
pub(crate) const MAX_CANVAS_PIXELS: usize = (2 * MAX_IMAGE_PIXELS) as usize;

/// The Python exception a step would raise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Raise {
    pub kind: Kind,
    pub message: String,
}

/// Python exception classes that decide what `Image.open` does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    SyntaxError,
    IndexError,
    TypeError,
    KeyError,
    EOFError,
    StructError,
    OSError,
    ValueError,
    ZeroDivisionError,
    OverflowError,
    MemoryError,
    DecompressionBombError,
    UnidentifiedImageError,
    /// Anything else (AssertionError, RuntimeError, an olefile error, ...).
    Other,
    /// This crate cannot do what Pillow would: decode a format it has no decoder for.
    Unsupported,
}

impl Raise {
    pub(crate) fn new(kind: Kind, message: impl Into<String>) -> Self {
        Raise {
            kind,
            message: message.into(),
        }
    }
    pub(crate) fn syntax(m: impl Into<String>) -> Self {
        Raise::new(Kind::SyntaxError, m)
    }
    pub(crate) fn os(m: impl Into<String>) -> Self {
        Raise::new(Kind::OSError, m)
    }
    pub(crate) fn value(m: impl Into<String>) -> Self {
        Raise::new(Kind::ValueError, m)
    }
    pub(crate) fn eof(m: impl Into<String>) -> Self {
        Raise::new(Kind::EOFError, m)
    }
    pub(crate) fn key() -> Self {
        Raise::new(Kind::KeyError, "")
    }
    pub(crate) fn type_error(m: impl Into<String>) -> Self {
        Raise::new(Kind::TypeError, m)
    }
    pub(crate) fn index_error() -> Self {
        Raise::new(Kind::IndexError, "index out of range")
    }
    pub(crate) fn struct_error() -> Self {
        Raise::new(Kind::StructError, "unpack requires a buffer of more bytes")
    }
    pub(crate) fn memory() -> Self {
        Raise::new(Kind::MemoryError, "")
    }
    pub(crate) fn unsupported(m: impl Into<String>) -> Self {
        Raise::new(Kind::Unsupported, m)
    }
    pub(crate) fn truncated() -> Self {
        Raise::os("image file is truncated")
    }
    /// `_get_oserror(err_code)` for a decoder's negative status (Image.core.getcodecstatus).
    pub(crate) fn decoder(code: i32) -> Self {
        let m = match code {
            -1 => "buffer overrun".to_string(),
            -2 => "broken data stream".to_string(),
            -3 => "unrecognized data stream contents".to_string(),
            -8 => "codec configuration error".to_string(),
            -9 => "out of memory".to_string(),
            _ => format!("decoder error {code}"),
        };
        Raise::os(format!("{m} when reading image file"))
    }
}

impl std::fmt::Display for Raise {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for Raise {}

/// ace3's `is_image(path)`: whether `Image.open` succeeds on these bytes. Any exception
/// (including `DecompressionBombError`) is False.
pub fn is_image(data: &[u8]) -> bool {
    open::open(data).is_ok()
}

/// What `Image.open` identified, for diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identified {
    pub format: &'static str,
    pub mode: String,
    pub size: (i64, i64),
}

/// `Image.open(...)`'s format, mode and size, or the exception it raises.
pub fn identify(data: &[u8]) -> Result<Identified, Raise> {
    let im = open::open(data)?;
    Ok(Identified {
        format: im.format,
        mode: im.mode.clone(),
        size: im.size,
    })
}

/// The hash `_image_hash` returns: the 256-bit row hash and the 256-bit column hash, each as
/// big-endian bytes (the row hash is the high half of Python's 512-bit integer).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ImageHash {
    pub row: [u8; 32],
    pub col: [u8; 32],
}

impl ImageHash {
    /// Python's integer as 64 big-endian bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(&self.row);
        b[32..].copy_from_slice(&self.col);
        b
    }

    /// `(a ^ b).bit_count()`.
    pub fn bits_different(&self, other: &ImageHash) -> u32 {
        self.to_bytes()
            .iter()
            .zip(other.to_bytes().iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum()
    }

    /// `format(h, "x")`: lowercase hex without leading zeros ("0" for zero).
    pub fn to_hex(&self) -> String {
        let mut s = String::new();
        for b in self.to_bytes() {
            s.push_str(&format!("{b:02x}"));
        }
        let t = s.trim_start_matches('0');
        if t.is_empty() {
            "0".to_string()
        } else {
            t.to_string()
        }
    }
}

/// ace3's `_image_hash`: open, decode, paste "RGBA"/"LA" over white, `convert("L")`, resize to
/// 17x17 with LANCZOS, and take the row and column differences.
///
/// An error is what Python would raise (the module then skips the file). Errors of kind
/// [`Kind::Unsupported`] are where Pillow would decode the image and this crate cannot: AVIF,
/// JPEG 2000, EPS (Ghostscript), DDS, BLP, ICNS, PSD, FLI, FITS, PCD, XPM, IPTC, SUN RLE,
/// FTEX DXT1, IM bit-packed data, TIFF compressions other than LZW, Deflate and PackBits (and
/// TIFF YCbCr), arithmetic-coded and lossless JPEG, and progressive JPEGs that libjpeg would
/// block-smooth. The opens of AVIF, JPEG 2000, EPS, DDS, BLP, ICNS, PSD, FITS, FPX and MIC are
/// approximations from their headers (see each plugin).
pub fn image_hash(data: &[u8]) -> Result<ImageHash, Raise> {
    let im = open::open(data)?;
    let canvas = im.loader.load()?;
    let gray = canvas.into_gray()?;
    let small = resample::resize_lanczos(gray, hash::IMAGE_SIZE + 1, hash::IMAGE_SIZE + 1);
    Ok(hash::dhash(&small.px))
}

#[cfg(test)]
mod tests;
