//! The row and column hashes, and the module's score.

use crate::ImageHash;

/// dhash.py's `IMAGE_SIZE`.
pub(crate) const IMAGE_SIZE: usize = 16;
/// dhash.py's `PIXEL_SIZE`: bits in a hash.
const PIXEL_SIZE: u32 = (IMAGE_SIZE * IMAGE_SIZE * 2) as u32;

/// The loop at the end of `_image_hash` over the 17x17 gray bytes.
pub(crate) fn dhash(grays: &[u8]) -> ImageHash {
    let width = IMAGE_SIZE + 1;
    let mut row = [0u8; 32];
    let mut col = [0u8; 32];
    let mut bit = 0;
    for y in 0..IMAGE_SIZE {
        for x in 0..IMAGE_SIZE {
            let offset = y * width + x;
            if grays[offset] < grays[offset + 1] {
                row[bit / 8] |= 0x80 >> (bit % 8);
            }
            if grays[offset] < grays[offset + width] {
                col[bit / 8] |= 0x80 >> (bit % 8);
            }
            bit += 1;
        }
    }
    ImageHash { row, col }
}

/// `100.0 - ((bits_different / PIXEL_SIZE) * 100.0)`, in the same float operations.
pub fn percent_similar(bits_different: u32) -> f64 {
    100.0 - ((bits_different as f64 / PIXEL_SIZE as f64) * 100.0)
}

/// `f"{x:.2f}"`. Rust's fixed precision formatting rounds the exact binary value half to
/// even, as Python's does; `inf` and `nan` are spelled as Python spells them.
pub fn format_percent(x: f64) -> String {
    if x.is_nan() {
        return "nan".to_string();
    }
    if x.is_infinite() {
        return if x > 0.0 { "inf" } else { "-inf" }.to_string();
    }
    format!("{x:.2}")
}

/// The score as `json.dumps` writes the float stored in the analysis details.
pub fn score_json(x: f64) -> String {
    ace_pycompat::json::float_repr(x)
}
