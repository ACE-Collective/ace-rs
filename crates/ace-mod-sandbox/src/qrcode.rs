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
//!
//! Its results are kept in the analysis cache for 30 days, as ace3's `cache_ttl` keeps them
//! (PLAN.md decision 26), a clean scan's among them, under its key's extended version: the filter's
//! entries, zbarimg's, Ghostscript's and pdfinfo's versions and OpenCV's, as ace3's
//! `extended_version` holds the filter's content hash and those tools' and `opencv-python`'s versions.
//! A scan that failed is skipped, so it is never kept. The file it adds is named after the one it
//! read (`output_paths`), which a hit names after the new root's.

use std::time::Duration;

use ace_mod_files::checks::is_pdf_file;
use ace_results::FileRole;
use ace_results::types::sandbox::QrCodeAnalysis;
use ace_results::{ObservableKind, Relationship, RelationshipKind, ResultEnvelope};
use ace_sdk::cache::{Cache, CachePaths};
use ace_sdk::takes::{Condition, Takes, TypeFact};
use ace_sdk::tools::{ToolOutput, ToolRun};
use ace_sdk::{List, ListSpec, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use opencv::core::{Mat, Vector};
use opencv::objdetect::QRCodeDetector;
use opencv::prelude::GraphicalCodeDetectorTraitConst;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::image::decode_bgr;
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

/// The paths the module names the file it adds at, for the file it read at `input`: one, ace3's
/// `<path>.qrcode`.
pub fn output_paths(input: &str) -> Vec<String> {
    vec![format!("{input}.qrcode")]
}

/// OpenCV's version, which the decoder's answers depend on: ace3 keys on `opencv-python`'s.
fn opencv_version() -> Vec<(&'static str, String)> {
    opencv::core::get_version_string()
        .map(|version| vec![("opencv", version)])
        .unwrap_or_default()
}

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
    /// ace3's `cache_ttl: 2592000`, 30 days.
    const CACHE: Option<Cache> = Some(Cache {
        paths: CachePaths::Named(output_paths),
        lists: &[QRCODE_FILTER],
        tools: &["pdfinfo", "gs", "zbarimg"],
        libraries: opencv_version,
        ..Cache::new(1, Duration::from_secs(30 * 24 * 3600))
    });
    type Output = QrCodeAnalysis;
    type Settings = QrCodeSettings;

    /// OpenCV runs on this thread alone, as ace3's script has it (`cv2.setNumThreads(1)`), set
    /// before the task process contains itself.
    fn init(_: &QrCodeSettings) -> Result<Self, ModuleError> {
        opencv::core::set_num_threads(1).map_err(ModuleError::other)?;
        Ok(QrCodeAnalyzer)
    }

    /// `custom_requirement` and the start of `execute_analysis`: an image Pillow opens, or a PDF,
    /// by the file's type (PLAN.md decision 25), as ace3's 2026-06-25 consult gate keeps the module
    /// off every other file before its analysis cache is asked.
    fn takes(_: &QrCodeSettings) -> Takes {
        Takes::everything()
            .and(Condition::not_empty(), "an empty file")
            .and(
                Condition::Any(vec![
                    Condition::type_fact(TypeFact::IsImage),
                    Condition::type_fact(TypeFact::IsPdfFile),
                ]),
                "not an image or a PDF",
            )
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

/// The page count in what pdfinfo printed, or None to render every page: when it was stopped,
/// exited non-zero or printed no count it can read.
fn pdfinfo_page_count(output: &ToolOutput, pdf: &str) -> Option<u64> {
    let returncode = output.returncode()?;
    // pdfinfo writes the metadata before it scans the pages and prints its count, so a run killed
    // during that scan can end in a forged "Pages:" line from the Title. Only a finished run's
    // last count is pdfinfo's own
    if returncode != 0 {
        let reason = crate::tool_failure_reason("pdfinfo", returncode, &output.stderr_text());
        tracing::warn!(path = pdf, "pdfinfo failed on {pdf}: {reason}");
        return None;
    }
    // pdfinfo prints the document's metadata, newlines and all, before its own "Pages:" line, so a
    // Title can print a "Pages:" line of its own. Nothing pdfinfo prints after its count is free
    // text: the last one is real
    let stdout = output.stdout_text();
    let line = stdout
        .split('\n')
        .rfind(|line| line.starts_with("Pages:"))?;
    // int(line.split(":")[1].strip())
    let value = ace_pycompat::pystr::strip(line.split(':').nth(1).unwrap_or_default());
    let count = python_int(value);
    if count.is_none() {
        // the count comes from the attacker's PDF, so a bad one is the file's problem
        tracing::warn!(
            path = pdf,
            "pdfinfo printed an unreadable page count for {pdf}: {line}"
        );
    }
    count
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
        Ok(pdfinfo_page_count(&output, &path))
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
        // an image or a PDF, as the declaration takes it (`takes`)
        let is_pdf = is_pdf_file(file.path.as_str(), &head(&file.local_path, 1024)?);
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
        let [target] = <[String; 1]>::try_from(output_paths(file.path.as_str())).expect("one path");
        if name_fits(&target) {
            let text: String = urls.iter().map(|url| format!("{url}\n")).collect();
            let mut new_file =
                ctx.write_file(&target, text.as_bytes(), FileRole::DOCUMENT_TEXT_QRCODE)?;
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

    /// What `f` logs, as the fmt subscriber writes it.
    fn logged<T>(f: impl FnOnce() -> T) -> (T, String) {
        #[derive(Clone, Default)]
        struct Logs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Logs {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("lock").extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let logs = Logs::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let value = tracing::subscriber::with_default(subscriber, f);
        let text = String::from_utf8(logs.0.lock().expect("lock").clone()).expect("text");
        (value, text)
    }

    fn pdfinfo(status: ace_sdk::tools::ToolStatus, stdout: &str) -> ToolOutput {
        ToolOutput {
            status,
            stdout: stdout.as_bytes().to_vec(),
            stderr: b"Syntax Error: bad xref\n".to_vec(),
            outputs: Default::default(),
        }
    }

    #[test]
    fn the_page_count_is_pdfinfos_last_pages_line() {
        use ace_sdk::tools::ToolStatus;
        // pdfinfo prints the metadata, newlines kept, before its own count: this Title printed a
        // count of 1, and only page 1 was rendered
        let output = pdfinfo(
            ToolStatus::Exited(0),
            "Title: x\nPages: 1\nCreator: y\nPages: 5\n",
        );
        let (count, logs) = logged(|| pdfinfo_page_count(&output, "a.pdf"));
        assert_eq!(count, Some(5));
        assert_eq!(logs, "");
    }

    #[test]
    fn a_page_count_that_cannot_be_read_renders_every_page() {
        use ace_sdk::tools::{ToolStatus, ToolStop};
        let cases = [
            // stopped: ace3's run_sandboxed_tool returns nothing, and nothing is logged
            (ToolStatus::Stopped(ToolStop::Timeout), "Pages: 3\n", None),
            (
                ToolStatus::Exited(0),
                "Title: x\nPages: many\n",
                Some("unreadable page count for a.pdf: Pages: many"),
            ),
            (ToolStatus::Exited(0), "Title: x\n", None),
            // killed after writing a forged count from the Title, before its own
            (
                ToolStatus::Signaled(6),
                "Title: x\nPages: 1\n",
                Some(
                    "pdfinfo failed on a.pdf: pdfinfo was killed by signal 6: Syntax Error: bad xref",
                ),
            ),
            (
                ToolStatus::Exited(1),
                "Title: x\nPages: 1\n",
                Some("pdfinfo failed on a.pdf: pdfinfo exited with status 1"),
            ),
        ];
        for (status, stdout, warning) in cases {
            let (count, logs) = logged(|| pdfinfo_page_count(&pdfinfo(status, stdout), "a.pdf"));
            assert_eq!(count, None, "{status:?} {stdout:?}");
            match warning {
                Some(warning) => {
                    assert!(logs.contains("WARN"), "{logs}");
                    assert!(logs.contains(warning), "{logs}");
                }
                None => assert_eq!(logs, "", "{status:?} {stdout:?}"),
            }
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
