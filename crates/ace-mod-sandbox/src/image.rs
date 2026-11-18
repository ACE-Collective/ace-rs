//! What ace3's ocr and qrcode modules read an image with, Pillow 13: whether `Image.open` takes a
//! file (`is_image`), and its pixels as `convert("RGB")` and `ImageOps.grayscale` give them.
//!
//! `is_image` follows Pillow's identification: each format it registers, in its order, by the first
//! bytes its plugin accepts and, where its plugin checks the header before taking the file, by that
//! check too. It leaves out the formats Pillow opens only through olefile (FlashPix, MIC) and those
//! with no signature whose checks are their whole parser (IM, IMT, IPTC, PCD, SPIDER); a file of one
//! of those isn't an image here. Pillow opens lazily, so a file whose header it takes is an image
//! even when its pixels don't decode, as `broken.png` shows.
//!
//! The pixels are OpenCV's decoders' (libjpeg-turbo, libpng, libtiff, libwebp), which are Pillow's
//! for JPEG, PNG and TIFF, with the orientation left as stored, as Pillow leaves it: `IMREAD_COLOR`
//! drops alpha and expands a palette, as `convert("RGB")` does, and grey is Pillow's own luma,
//! `(19595 R + 38470 G + 7471 B + 0x8000) >> 16`.

use std::io::Read;
use std::path::Path;

use opencv::core::{Mat, MatTraitConst, MatTraitConstManual, Vector};
use opencv::imgcodecs;

/// The format Pillow would open a file's first 1024 bytes as (`ace_mod_files::pillow`), which the
/// type step also records as the file's `is_image` (PLAN.md decision 25).
pub use ace_mod_files::pillow::identify;

/// `PIL.Image.open(path)` succeeds.
pub fn is_image(path: &Path) -> std::io::Result<bool> {
    let mut head = Vec::new();
    std::fs::File::open(path)?
        .take(1024)
        .read_to_end(&mut head)?;
    Ok(identify(&head).is_some())
}

/// An image's pixels, 8-bit BGR, as `IMREAD_COLOR` with the orientation left as stored decodes it.
/// None for a file OpenCV can't decode.
pub fn decode_bgr(path: &Path) -> Result<Option<Mat>, opencv::Error> {
    let bytes = std::fs::read(path).map_err(|e| opencv::Error::new(0, e.to_string()))?;
    let buffer = Vector::<u8>::from_slice(&bytes);
    let image = imgcodecs::imdecode(
        &buffer,
        imgcodecs::IMREAD_COLOR | imgcodecs::IMREAD_IGNORE_ORIENTATION,
    )?;
    Ok((!image.empty()).then_some(image))
}

/// Pillow's `convert("L")` of an RGB image given as BGR.
pub fn luma(bgr: &Mat) -> Result<Mat, opencv::Error> {
    let rows = bgr.rows();
    let cols = bgr.cols();
    let data = bgr.data_bytes()?;
    let mut gray = vec![0u8; (rows * cols) as usize];
    for (i, pixel) in data.as_chunks::<3>().0.iter().enumerate() {
        let (b, g, r) = (
            u32::from(pixel[0]),
            u32::from(pixel[1]),
            u32::from(pixel[2]),
        );
        gray[i] = ((r * 19595 + g * 38470 + b * 7471 + 0x8000) >> 16) as u8;
    }
    let flat = Mat::from_slice(&gray)?;
    flat.reshape(1, rows)?.try_clone()
}
