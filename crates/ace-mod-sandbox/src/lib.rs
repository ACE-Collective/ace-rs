//! The modules of PLAN.md 7.5 batches 10 and 11 that run tools in the sandbox runner
//! (`ace_sdk::tools`, `ace_pool::tools`), each a port of ace3's. Batch 10's: `pdftotext` (poppler's
//! pdftotext), `exif` (ExifTool), `qrcode` (pdfinfo, Ghostscript and zbarimg, with OpenCV's QR
//! decoder in the task) and `ocr` (tesseract, with OpenCV's preprocessing in the task). Batch 11's
//! unpackers and decompilers: `java_class_decompiler` (CFR on the JVM), `upx`, `autoit`
//! (unautoit), `de4dot` (de4dotEx) and `ilspy` (ilspycmd), the last two on .NET. Batch 12's macOS
//! images: `dmg_analyzer` (dmg2img and 7z) and `cve_2021_30657_analyzer` (7z). They run on the
//! `sandbox` pool, whose image carries the tools at ace3's versions (docs/modules.md, *External
//! tools*).

pub mod autoit;
pub mod dmg;
pub mod dotnet;
pub mod exif;
pub mod image;
pub mod java;
pub mod ocr;
pub mod pdftotext;
pub mod pprint;
pub mod qrcode;
pub mod upx;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use ace_results::{NewFile, ObservableKind, ObservableRef};
use ace_sdk::tools::ToolOutput;
use ace_sdk::{InputFile, Observable};

pub use autoit::AutoItAnalyzer;
pub use dmg::{Cve202130657Analyzer, DmgAnalyzer};
pub use dotnet::{De4dotAnalyzer, IlspyAnalyzer};
pub use exif::ExifAnalyzer;
pub use java::JavaClassDecompiler;
pub use ocr::OcrAnalyzer;
pub use pdftotext::PdfTextAnalyzer;
pub use qrcode::QrCodeAnalyzer;
pub use upx::UpxAnalyzer;

/// The most files a module adds from one run: ace3's limit of file observables in a root
/// (`maximum_observable_count`), which ace4's core doesn't have.
pub const MAX_FILES: usize = 500;

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

/// Why the runner stopped a run, for a result that records it; empty for a run that ended.
fn stopped_reason(output: &ToolOutput) -> &'static str {
    output.stopped().map_or("", |stop| stop.describe())
}

/// ace3's `fixed_directives`, which `copy_directives_to` leaves behind.
const FIXED_DIRECTIVES: [&str; 1] = ["archive"];

/// `copy_directives_to`: the observable's directives but the fixed ones, and its `yara_meta` types,
/// which ace3 keeps among its directives, onto a file it added.
fn copy_directives(observable: &Observable, file: &InputFile, to: &mut NewFile) {
    for directive in &observable.directives {
        if !FIXED_DIRECTIVES.contains(&directive.as_str()) && !to.directives.contains(directive) {
            to.directives.push(directive.clone());
        }
    }
    for meta in &file.yara_meta {
        if !to.yara_meta.contains(meta) {
            to.yara_meta.push(meta.clone());
        }
    }
}

/// `saq.util.strings.format_item_list_for_summary`, with its 20 items.
fn item_list(items: &[String]) -> String {
    let mut result = items[..items.len().min(20)].join(", ");
    if items.len() > 20 {
        result.push_str(&format!(" + {} more", items.len() - 20));
    }
    result
}
