//! ace3's `QRCodeAnalyzer` (`saq/modules/file_analysis/qrcode.py`): the URLs in the QR codes of an
//! image, or of the first and last pages of a PDF, for crawling.
//!
//! A PDF's pages are counted with poppler's pdfinfo and rendered to PNG with Ghostscript, then each
//! page or the image is scanned with zbarimg, all in the sandbox runner. Where zbarimg finds no URL,
//! OpenCV's QR decoder reads the page and its inverse, here in the task as ace3's
//! `bin/qr_decode_opencv.py` reads them in a process of its own; then zbarimg scans the inverse,
//! which the task writes as Pillow's `ImageOps.invert` would, and OpenCV's inverse is the fallback.
//!
//! ace3 drops a URL a line of its analysts' `qrcode.filter` matches, case-blind. That file is the
//! analyst-edited list `qrcode_filter` here (PLAN.md 5.14), whose regex entries are the `regex`
//! crate's rather than Python's `re`.

use std::time::Duration;

use ace_mod_files::checks::is_pdf_file;
use ace_results::types::sandbox::QrCodeAnalysis;
use ace_results::{ObservableKind, Relationship, RelationshipKind, ResultEnvelope, YaraMeta};
use ace_sdk::tools::ToolRun;
use ace_sdk::{List, ListSpec, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use opencv::core::{Mat, Vector};
use opencv::objdetect::QRCodeDetector;
use opencv::prelude::GraphicalCodeDetectorTraitConst;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::image::{decode_bgr, is_image};
use crate::{head, name_fits, source};

/// ace3's `qrcode.filter`, which its analysts edit.
pub const QRCODE_FILTER: ListSpec = ListSpec {
    name: "qrcode_filter",
    description: "URLs read from a QR code that an entry matches are dropped. ace3's qrcode.filter, a \
                  regex a line, matched anywhere in the URL without case.",
    typed: false,
};

/// zbarimg's exit codes for a scan that finished: 0 found a symbol, 4 found none.
const ZBARIMG_DONE: [i32; 2] = [0, 4];

/// ace3's section of the module, but for `filter_path`: the filter is a list.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct QrCodeSettings {
    /// Pages scanned from the start of a PDF.
    pub pdf_first_pages: u32,
    /// Pages scanned from its end.
    pub pdf_last_pages: u32,
    /// Seconds each tool may run.
    pub timeout: u64,
}

impl Default for QrCodeSettings {
    /// ace3's `saq.default.yaml`.
    fn default() -> Self {
        QrCodeSettings {
            pdf_first_pages: 3,
            pdf_last_pages: 3,
            timeout: 30,
        }
    }
}

/// The qrcode module.
pub struct QrCodeAnalyzer;

impl Module for QrCodeAnalyzer {
    const NAME: &'static str = "qrcode";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const TOOLS: &'static [&'static str] = &["pdfinfo", "gs", "zbarimg"];
    const LISTS: &'static [ListSpec] = &[QRCODE_FILTER];
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(300),
        memory_mb: 2048,
        cpu_seconds: 300,
    };
    type Output = QrCodeAnalysis;
    type Settings = QrCodeSettings;

    /// OpenCV runs on this thread alone, as ace3's script has it (`cv2.setNumThreads(1)`), set
    /// before the task process contains itself.
    fn init(_: &QrCodeSettings) -> Result<Self, ModuleError> {
        opencv::core::set_num_threads(1).map_err(ModuleError::other)?;
        Ok(QrCodeAnalyzer)
    }
}

/// `_extract_valid_urls`: each line that isn't empty, filtered or without a `.` or a `/`.
fn valid_urls(stdout: &str, filter: &List, now: chrono::DateTime<chrono::Utc>) -> Vec<String> {
    let mut urls = Vec::new();
    for line in stdout.split('\n') {
        if line.is_empty() {
            continue;
        }
        if matches!(filter.find(None, line, now), Ok(Some(_))) {
            continue;
        }
        if !line.contains('.') && !line.contains('/') {
            tracing::info!(line, "a QR code that is probably not a URL");
            continue;
        }
        urls.push(line.to_owned());
    }
    urls
}

/// The page images gs wrote as `<prefix><n>.png`, in page order (`_rendered_pages`).
fn rendered(
    outputs: &std::collections::BTreeMap<String, std::path::PathBuf>,
    prefix: &str,
) -> Vec<std::path::PathBuf> {
    let mut pages: Vec<(u64, std::path::PathBuf)> = outputs
        .iter()
        .filter_map(|(name, path)| {
            let number = name.strip_prefix(prefix)?.strip_suffix(".png")?;
            (!number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
                .then(|| number.parse().ok())
                .flatten()
                .map(|n| (n, path.clone()))
        })
        .collect();
    pages.sort();
    pages.into_iter().map(|(_, path)| path).collect()
}

struct Scanner<'a> {
    ctx: &'a TaskContext<QrCodeSettings>,
    timeout: Duration,
    inverted: u32,
}

impl Scanner<'_> {
    /// `_scan_image`: zbarimg's stdout when the scan finished, None when it failed.
    fn zbarimg(&self, image: &std::path::Path) -> Result<Option<String>, ModuleError> {
        let path = image.display().to_string();
        let output = self.ctx.run_tool(
            ToolRun::new("zbarimg", ["-q", "--raw", "--nodbus", path.as_str()])
                .read(image)
                .timeout(self.timeout),
        )?;
        match output.returncode() {
            Some(code) if ZBARIMG_DONE.contains(&code) => Ok(Some(output.stdout_text())),
            Some(code) => {
                tracing::warn!(code, "zbarimg failed");
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// `_scan_inverted_image`: the image as RGB, inverted, saved as a PNG and scanned.
    fn inverted(&mut self, image: &std::path::Path) -> Result<Option<String>, ModuleError> {
        let Some(scratch) = self.ctx.scratch_dir() else {
            return Ok(None);
        };
        let decoded = match decode_bgr(image) {
            Ok(Some(decoded)) => decoded,
            Ok(None) | Err(_) => {
                tracing::warn!("unable to invert the image");
                return Ok(None);
            }
        };
        let mut inverse = Mat::default();
        let mut png = Vector::<u8>::new();
        let encoded = opencv::core::bitwise_not_def(&decoded, &mut inverse)
            .and_then(|()| opencv::imgcodecs::imencode_def(".png", &inverse, &mut png));
        if !matches!(encoded, Ok(true)) {
            tracing::warn!("unable to save the inverted image");
            return Ok(None);
        }
        self.inverted += 1;
        let path = scratch.join(format!("inverted-{}.png", self.inverted));
        std::fs::write(&path, png.as_slice())?;
        let scanned = self.zbarimg(&path);
        std::fs::remove_file(&path).ok();
        scanned
    }
}

/// `qr_decode_opencv.py`'s `_decode`: what `detectAndDecode` reads, then each of
/// `detectAndDecodeMulti`'s, without the empty ones or one twice.
fn opencv_decode(image: &Mat) -> Result<Vec<String>, opencv::Error> {
    let detector = QRCodeDetector::default()?;
    let mut decoded: Vec<String> = Vec::new();
    let single = detector.detect_and_decode_def(image)?;
    decoded.push(String::from_utf8_lossy(&single).into_owned());
    let mut multi = Vector::<String>::new();
    detector.detect_and_decode_multi_def(image, &mut multi)?;
    decoded.extend(multi);
    let mut seen: Vec<String> = Vec::new();
    for code in decoded {
        if !code.is_empty() && !seen.contains(&code) {
            seen.push(code);
        }
    }
    Ok(seen)
}

/// `_scan_image_with_opencv`: the codes OpenCV reads in the image and in its inverse, each joined
/// with newlines. An image `cv2.imread` can't read has none.
fn scan_with_opencv(image: &std::path::Path) -> Option<(String, String)> {
    let path = image.to_str()?;
    let read = opencv::imgcodecs::imread(path, opencv::imgcodecs::IMREAD_COLOR).ok()?;
    if opencv::core::MatTraitConst::empty(&read) {
        return Some((String::new(), String::new()));
    }
    let mut inverse = Mat::default();
    opencv::core::bitwise_not_def(&read, &mut inverse).ok()?;
    let normal = opencv_decode(&read).ok()?;
    let inverted = opencv_decode(&inverse).ok()?;
    if !normal.is_empty() || !inverted.is_empty() {
        tracing::info!("OpenCV read a QR code zbarimg couldn't");
    }
    Some((normal.join("\n"), inverted.join("\n")))
}

impl QrCodeAnalyzer {
    /// `_get_pdf_page_count`.
    fn page_count(
        &self,
        ctx: &TaskContext<QrCodeSettings>,
        pdf: &std::path::Path,
        timeout: Duration,
    ) -> Result<Option<u64>, ModuleError> {
        let path = pdf.display().to_string();
        let output = ctx.run_tool(
            ToolRun::new("pdfinfo", [path.as_str()])
                .read(pdf)
                .timeout(timeout),
        )?;
        if output.stopped().is_some() {
            return Ok(None);
        }
        for line in output.stdout_text().split('\n') {
            if line.starts_with("Pages:") {
                // int(line.split(":")[1].strip())
                let value = line.split(':').nth(1).unwrap_or_default();
                let value = ace_pycompat::pystr::strip(value);
                return Ok(python_int(value));
            }
        }
        Ok(None)
    }

    /// `_render_pdf_pages` and `_render_pdf_to_pngs`: the pages to scan, in order.
    fn render(
        &self,
        ctx: &TaskContext<QrCodeSettings>,
        pdf: &std::path::Path,
    ) -> Result<Vec<std::path::PathBuf>, ModuleError> {
        let settings = ctx.settings();
        let timeout = Duration::from_secs(settings.timeout);
        let path = pdf.display().to_string();
        let gs = |first: Option<(u64, u64)>,
                  pattern: &str|
         -> Result<
            Option<std::collections::BTreeMap<String, std::path::PathBuf>>,
            ModuleError,
        > {
            let mut args = vec![
                "-sDEVICE=pngalpha".to_owned(),
                "-o".to_owned(),
                pattern.to_owned(),
                "-r144".to_owned(),
            ];
            if let Some((from, to)) = first {
                args.push(format!("-dFirstPage={from}"));
                args.push(format!("-dLastPage={to}"));
            }
            args.push(path.clone());
            let output = ctx.run_tool(
                ToolRun::new("gs", args)
                    .read(pdf)
                    .keep_all()
                    .timeout(timeout),
            )?;
            Ok(match output.returncode() {
                Some(0) => Some(output.outputs),
                // the fallback's pages count whatever gs exited with
                Some(_) if first.is_none() => Some(output.outputs),
                _ => None,
            })
        };
        let (first_n, last_n) = (
            u64::from(settings.pdf_first_pages),
            u64::from(settings.pdf_last_pages),
        );
        if let Some(total) = self.page_count(ctx, pdf, timeout)? {
            let mut pages = Vec::new();
            if total <= first_n + last_n {
                if let Some(outputs) = gs(Some((1, total)), "page-%d.png")? {
                    pages = rendered(&outputs, "page-");
                }
            } else {
                if let Some(outputs) = gs(Some((1, first_n)), "first-%d.png")? {
                    pages.extend(rendered(&outputs, "first-"));
                }
                let start = total - last_n + 1;
                if let Some(outputs) = gs(Some((start, total)), "last-%d.png")? {
                    pages.extend(rendered(&outputs, "last-"));
                }
            }
            if !pages.is_empty() {
                return Ok(pages);
            }
            tracing::warn!("selective rendering failed, so every page is rendered");
        }
        let Some(outputs) = gs(None, "page-%d.png")? else {
            return Ok(Vec::new());
        };
        let pages = rendered(&outputs, "page-");
        let total = pages.len() as u64;
        if total > first_n + last_n {
            let keep: Vec<std::path::PathBuf> = pages[..first_n as usize]
                .iter()
                .chain(&pages[pages.len() - last_n as usize..])
                .cloned()
                .collect();
            return Ok(pages.into_iter().filter(|p| keep.contains(p)).collect());
        }
        Ok(pages)
    }
}

/// Python's `int(text)` of a stripped decimal, which may have a sign and underscores between
/// digits. None where it raises.
fn python_int(text: &str) -> Option<u64> {
    let digits = text.strip_prefix('+').unwrap_or(text);
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits.chars().all(|c| c.is_ascii_digit() || c == '_')
    {
        return None;
    }
    digits.replace('_', "").parse().ok()
}

impl Parser for QrCodeAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<QrCodeSettings>,
    ) -> Result<Outcome<QrCodeAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        if file.size == 0 {
            return Ok(Outcome::Skipped("an empty file".to_owned()));
        }
        let is_pdf = is_pdf_file(file.path.as_str(), &head(&file.local_path, 1024)?);
        if !is_image(&file.local_path)? && !is_pdf {
            return Ok(Outcome::Skipped("not an image or a PDF".to_owned()));
        }
        let filter = ctx.list(&QRCODE_FILTER)?;
        let targets = if is_pdf {
            self.render(ctx, &file.local_path)?
        } else {
            vec![file.local_path.clone()]
        };
        if targets.is_empty() {
            return Ok(Outcome::Skipped("no page rendered".to_owned()));
        }
        let mut scanner = Scanner {
            ctx,
            timeout: Duration::from_secs(ctx.settings().timeout),
            inverted: 0,
        };
        let now = ctx.now();
        let mut normal_urls = Vec::new();
        let mut inverted_urls = Vec::new();
        let mut scan_failed = false;
        for target in &targets {
            ctx.check_cancelled()?;
            let stdout = scanner.zbarimg(target)?;
            if stdout.is_none() {
                scan_failed = true;
            }
            let mut page_urls = match &stdout {
                Some(text) if !text.is_empty() => valid_urls(text, filter, now),
                _ => Vec::new(),
            };
            let mut opencv = None;
            if stdout.is_some() && page_urls.is_empty() {
                opencv = scan_with_opencv(target);
                match &opencv {
                    None => scan_failed = true,
                    Some((normal, _)) => page_urls = valid_urls(normal, filter, now),
                }
            }
            if !page_urls.is_empty() {
                normal_urls.extend(page_urls);
            } else {
                let inverted = scanner.inverted(target)?;
                if inverted.is_none() {
                    scan_failed = true;
                }
                let mut inverted_page_urls = match &inverted {
                    Some(text) if !text.is_empty() => valid_urls(text, filter, now),
                    _ => Vec::new(),
                };
                if inverted_page_urls.is_empty()
                    && let Some((_, inverse)) = &opencv
                {
                    inverted_page_urls = valid_urls(inverse, filter, now);
                }
                inverted_urls.extend(inverted_page_urls);
            }
        }
        if normal_urls.is_empty() && inverted_urls.is_empty() {
            // a clean negative is a result; a scan that failed is unknown
            if scan_failed {
                return Ok(Outcome::Skipped("a scan failed".to_owned()));
            }
            return Ok(Outcome::Done(
                ResultEnvelope::new(QrCodeAnalysis::default()),
            ));
        }
        let (urls, inverted) = if normal_urls.is_empty() {
            (inverted_urls, true)
        } else {
            (normal_urls, false)
        };
        let mut result = ResultEnvelope::new(QrCodeAnalysis {
            extracted_text: Some(urls.join(", ")),
            inverted,
        });
        result.summary = Some(format!(
            "QR Code Analysis: {}{}",
            if inverted { "INVERTED: " } else { "" },
            urls.join(", ")
        ));
        let target = format!("{}.qrcode", file.path.as_str());
        if name_fits(&target) {
            let text: String = urls.iter().map(|url| format!("{url}\n")).collect();
            let mut new_file = ctx.write_file(
                &target,
                text.as_bytes(),
                &[YaraMeta::new("type", "document.text.qrcode").map_err(ModuleError::other)?],
            )?;
            new_file.relationships.push(Relationship::new(
                RelationshipKind::ExtractedFrom,
                source(file),
            ));
            new_file.add_directive("extract_urls");
            new_file.add_directive("crawl_extracted_urls");
            new_file
                .exclude_modules
                .push("file_hash_analyzer".to_owned());
            new_file.tags.push("qr-code".to_owned());
            if inverted {
                new_file.tags.push("qr-code-inverted".to_owned());
            }
            result.files.push(new_file);
        }
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_count_is_pythons_int() {
        assert_eq!(python_int("12"), Some(12));
        assert_eq!(python_int("1_000"), Some(1000));
        assert_eq!(python_int("+3"), Some(3));
        for bad in ["", "x", "1.0", "_1", "1__0"] {
            assert_eq!(python_int(bad), None, "{bad}");
        }
    }

    #[test]
    fn only_lines_like_urls_are_kept() {
        let empty = List::empty("qrcode_filter");
        let now = chrono::Utc::now();
        assert_eq!(
            valid_urls(
                "https://a.example/x\n\nWIFI:S:home\nexample.com\n",
                &empty,
                now
            ),
            ["https://a.example/x", "example.com"]
        );
    }
}
