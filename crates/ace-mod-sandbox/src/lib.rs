//! The modules of PLAN.md 7.5 batch 10 that run tools in the sandbox runner (`ace_sdk::tools`,
//! `ace_pool::tools`), each a port of ace3's: `pdftotext` (poppler's pdftotext), `exif` (ExifTool),
//! `qrcode` (pdfinfo, Ghostscript and zbarimg, with OpenCV's QR decoder in the task) and `ocr`
//! (tesseract, with OpenCV's preprocessing in the task). They run on the `sandbox` pool, whose
//! image carries the tools at ace3's versions (docs/modules.md, *External tools*).

pub mod exif;
pub mod image;
pub mod ocr;
pub mod pdftotext;
pub mod pprint;
pub mod qrcode;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use ace_results::{ObservableKind, ObservableRef};
use ace_sdk::InputFile;

pub use exif::ExifAnalyzer;
pub use ocr::OcrAnalyzer;
pub use pdftotext::PdfTextAnalyzer;
pub use qrcode::QrCodeAnalyzer;

/// A file name's limit, which ace3 meets on its filesystem.
const NAME_MAX: usize = 255;

/// The first `n` bytes of a file.
fn head(path: &Path, n: u64) -> std::io::Result<Vec<u8>> {
    let mut head = Vec::new();
    File::open(path)?.take(n).read_to_end(&mut head)?;
    Ok(head)
}

/// Whether every name in an alert path is within `NAME_MAX`.
fn name_fits(path: &str) -> bool {
    path.split('/').all(|name| name.len() <= NAME_MAX)
}

/// The observable a file stands for.
fn source(file: &InputFile) -> ObservableRef {
    ObservableRef::new(ObservableKind::File, file.sha256.to_hex())
}
