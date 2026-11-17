//! The results of PLAN.md 7.5 batch 10's modules that run tools, which `ace-mod-sandbox` writes,
//! with ace3's keys: `OCRAnalysis` (`saq/modules/file_analysis/ocr.py`), `QRCodeAnalysis`
//! (`qrcode.py`), `ExifAnalysis` (`exif.py`) and `PDFTextAnalysis` (`pdf.py`).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of an `ocr_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OcrAnalysis {
    /// True when tesseract found text, which the module wrote to a file.
    pub ocr: bool,
}

impl AnalysisType for OcrAnalysis {
    const NAME: &'static str = "ocr_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "ocr";
}

/// The details of a `qr_code_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QrCodeAnalysis {
    /// The URLs the codes held, joined with `, `. None when none was found.
    pub extracted_text: Option<String>,
    /// True when they came from the image inverted.
    pub inverted: bool,
}

impl AnalysisType for QrCodeAnalysis {
    const NAME: &'static str = "qr_code_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "qrcode";
}

/// The details of an `exif_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExifAnalysis {
    /// What `exiftool -j -G -n` printed for the file, its `Group:Tag` names as keys. Empty when
    /// exiftool gave nothing, and the result's `error` then says why: its own error, its last line
    /// on stderr, or that it didn't finish.
    pub exifdata: serde_json::Map<String, serde_json::Value>,
    /// Where the pretty-printed copy went, as ace3 names it: `<file>.exif`. Only when exiftool
    /// succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_dir: Option<String>,
}

impl AnalysisType for ExifAnalysis {
    const NAME: &'static str = "exif_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "exif";
}

/// The details of a `pdf_text_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PdfTextAnalysis {
    /// What pdftotext wrote to stdout and stderr. None when it didn't finish.
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    /// The text file's sha256, when pdftotext wrote one.
    pub output_path: Option<String>,
}

impl AnalysisType for PdfTextAnalysis {
    const NAME: &'static str = "pdf_text_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "pdftotext";
}
