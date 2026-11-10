//! ace3's `OCRAnalyzer` (`saq/modules/file_analysis/ocr.py`, with `saq/ocr.py`): the text tesseract
//! reads in an image that carries the `ocr` directive, for URL extraction and YARA.
//!
//! The image is read as Pillow reads it and made grey, scaled up and sharpened when it's narrow,
//! inverted when it's dark and given a white border, with OpenCV in the task as ace3 does it; then
//! tesseract reads it, and again once OpenCV has denoised it, in the sandbox runner. ace3's
//! pytesseract runs tesseract on the image saved as a PNG; here the task saves it with OpenCV, and
//! tesseract reads the same pixels. Each pass's text is cleaned up as ace3 cleans it, and joined over
//! its line breaks by whether each line's last word is in the en_US Hunspell dictionary, which ace3
//! asks through enchant and the task through `spellbook`.

use std::time::Duration;

use ace_results::types::sandbox::OcrAnalysis;
use ace_results::{ObservableKind, Relationship, RelationshipKind, ResultEnvelope, YaraMeta};
use ace_sdk::tools::ToolRun;
use ace_sdk::{Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use opencv::core::{BORDER_CONSTANT, Mat, MatTraitConst, Scalar, Size, Vector};
use opencv::{imgcodecs, imgproc, photo};
use regex::Regex;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::image::{decode_bgr, is_image, luma};
use crate::{name_fits, source};

/// The dictionary ace3's enchant finds for `en_US`: Hunspell's, hunspell-en-us 2020.12.07.
const DICTIONARY: (&str, &str) = (
    "/usr/share/hunspell/en_US.aff",
    "/usr/share/hunspell/en_US.dic",
);

/// ace3's section of the module.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct OcrSettings {
    /// `OMP_THREAD_LIMIT` for tesseract; none leaves it unset.
    pub omp_thread_limit: Option<u32>,
    /// The largest image read, ace3's `file_size_limit`, in bytes.
    pub file_size_limit: u64,
    /// Seconds each tesseract pass may run. ace3's pytesseract gives it no limit; the task's deadline
    /// is the bound.
    pub timeout: u64,
}

impl Default for OcrSettings {
    /// ace3's `saq.default.yaml`. Its `valid_analysis_modes` and `valid_alert_types` are empty, which
    /// restricts nothing, and aren't here.
    fn default() -> Self {
        OcrSettings {
            omp_thread_limit: Some(1),
            file_size_limit: 104_857_600,
            timeout: 120,
        }
    }
}

/// The ocr module.
pub struct OcrAnalyzer {
    dictionary: spellbook::Dictionary,
    cleanup: Cleanup,
}

impl Module for OcrAnalyzer {
    const NAME: &'static str = "ocr";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const REQUIRED_DIRECTIVES: &'static [&'static str] = &["ocr"];
    const TOOLS: &'static [&'static str] = &["tesseract"];
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(300),
        memory_mb: 3072,
        cpu_seconds: 300,
    };
    type Output = OcrAnalysis;
    type Settings = OcrSettings;

    /// Loads the dictionary, and sets OpenCV to this thread alone, before the task process contains
    /// itself.
    fn init(_: &OcrSettings) -> Result<Self, ModuleError> {
        opencv::core::set_num_threads(1).map_err(ModuleError::other)?;
        let read = |path: &str| {
            std::fs::read_to_string(path).map_err(|e| ModuleError::other(format!("{path}: {e}")))
        };
        let dictionary = spellbook::Dictionary::new(&read(DICTIONARY.0)?, &read(DICTIONARY.1)?)
            .map_err(|e| ModuleError::other(format!("the en_US dictionary: {e}")))?;
        Ok(OcrAnalyzer {
            dictionary,
            cleanup: Cleanup::new(),
        })
    }
}

/// `get_image_text`'s clean-up of tesseract's text, and `fix_defanged_indicators`.
struct Cleanup {
    https: Regex,
    http: Regex,
    pass1: Vec<(Regex, &'static str)>,
    pass2: Vec<(Regex, &'static str)>,
}

/// `_UNICODE_CHARMAP`: one character for another.
const CHARMAP: &[(char, char)] = &[
    ('\u{2014}', '-'),
    ('\u{2013}', '-'),
    ('\u{2018}', '\''),
    ('\u{2019}', '\''),
    ('\u{201A}', ','),
    ('\u{201C}', '"'),
    ('\u{201D}', '"'),
    ('\u{201E}', '"'),
    ('\u{2032}', '\''),
    ('\u{2033}', '"'),
    ('\u{2010}', '-'),
    ('\u{2011}', '-'),
    ('\u{2012}', '-'),
    ('\u{2015}', '-'),
    ('\u{00AB}', '"'),
    ('\u{00BB}', '"'),
    ('\u{2039}', '\''),
    ('\u{203A}', '\''),
    ('\u{00B7}', '.'),
    ('\u{2022}', '*'),
    ('\u{00D7}', 'x'),
    ('\u{00F7}', '/'),
];

/// `_UNICODE_MULTI`, in its order.
const MULTI: &[(&str, &str)] = &[
    ("\u{2026}", "..."),
    ("\u{00A9}", "(c)"),
    ("\u{00AE}", "(R)"),
    ("\u{2122}", "(TM)"),
    ("\u{2120}", "(SM)"),
];

impl Cleanup {
    fn new() -> Cleanup {
        let re = |pattern: &str| Regex::new(pattern).expect("a fixed pattern");
        Cleanup {
            https: re(r"h(t|i)(t|i)(p|o)s(:|.)//"),
            http: re(r"h(t|i)(t|i)(p|o)(:|.)//"),
            pass1: vec![
                (re(r"[\[{lf]\.[\]}JI]"), "[.]"),
                (re(r"[\[{]\.\s[\]}JI]"), "[.]"),
                (re(r"\[\.\s(\w+)[lf]\s?[JI]"), "[.]${1}[.]"),
                (re(r"[\[{lf]@[\]}JI]"), "[@]"),
                (re(r"[\[{]@\s?[\]}JI]"), "[@]"),
            ],
            pass2: vec![
                (re(r"(\[\.\]\w*)[lf]\.\s?[JI]"), "${1}[.]"),
                (re(r"(@\w*)[lf]\.\s?[JI]"), "${1}[.]"),
            ],
        }
    }

    fn clean(&self, text: &str) -> String {
        if text.is_empty() {
            return String::new();
        }
        let text = self.https.replace_all(text, "https://");
        let text = self.http.replace_all(&text, "http://");
        let mut text: String = text
            .chars()
            .map(|c| {
                CHARMAP
                    .iter()
                    .find(|(from, _)| *from == c)
                    .map_or(c, |(_, to)| *to)
            })
            .collect();
        for (from, to) in MULTI {
            text = text.replace(from, to);
        }
        for (pattern, replacement) in &self.pass1 {
            text = pattern.replace_all(&text, *replacement).into_owned();
        }
        // each pass until nothing changes
        loop {
            let before = text.clone();
            for (pattern, replacement) in &self.pass2 {
                text = pattern.replace_all(&text, *replacement).into_owned();
            }
            if text == before {
                return text;
            }
        }
    }
}

/// Hunspell's `spell`, which spellbook gives but for the word breaks Hunspell falls back to: an
/// affix file with no `BREAK` lines, as en_US's, breaks words at `-`, `^-` and `-$`, and a word
/// whose parts on either side of a break are words is one (`hunspell.cxx`, `HunspellImpl::spell`).
fn check(dictionary: &spellbook::Dictionary, word: &str) -> bool {
    if dictionary.check(word) {
        return true;
    }
    if word.matches('-').count() >= 10 {
        return false;
    }
    // a dash at the start or the end
    if word.len() > 1 {
        if let Some(rest) = word.strip_prefix('-')
            && check(dictionary, rest)
        {
            return true;
        }
        if let Some(rest) = word.strip_suffix('-')
            && check(dictionary, rest)
        {
            return true;
        }
    }
    // a dash inside: the part after it, then the part before
    let Some(found) = word.find('-') else {
        return false;
    };
    if found == 0 || found + 1 >= word.len() {
        return false;
    }
    if let Some(second) = word[found + 1..].find('-').map(|i| i + found + 1)
        && second + 1 < word.len()
    {
        // the second dash, to find words that have one
        if check(dictionary, &word[second + 1..]) && check(dictionary, &word[..second]) {
            return true;
        }
    }
    check(dictionary, &word[found + 1..]) && check(dictionary, &word[..found])
}

/// `remove_line_wrapping`: each line's last word decides whether a space follows it.
fn remove_line_wrapping(text: &str, dictionary: &spellbook::Dictionary) -> String {
    let mut unwrapped = String::new();
    for line in ace_pycompat::pystr::splitlines(text) {
        let Some(last) = line.split_whitespace().last() else {
            continue;
        };
        if check(dictionary, last) {
            unwrapped.push_str(line);
            unwrapped.push(' ');
        } else {
            unwrapped.push_str(line);
        }
    }
    unwrapped
}

fn cv(error: opencv::Error) -> ModuleError {
    ModuleError::other(error.to_string())
}

/// The image as ace3's preprocessing leaves it, from its grey form.
fn preprocess(mut gray: Mat) -> Result<Mat, opencv::Error> {
    let width = gray.cols();
    // get_scale_factor: up to 1500 wide, at most 4 times
    if width < 1500 {
        let factor = (1500.0 / f64::from(width)).min(4.0);
        if factor > 1.0 {
            let mut scaled = Mat::default();
            imgproc::resize(
                &gray,
                &mut scaled,
                Size::default(),
                factor,
                factor,
                imgproc::INTER_CUBIC,
            )?;
            // sharpen_image: an unsharp mask
            let mut blurred = Mat::default();
            imgproc::gaussian_blur_def(&scaled, &mut blurred, Size::new(0, 0), 3.0)?;
            let mut sharpened = Mat::default();
            opencv::core::add_weighted_def(&scaled, 2.0, &blurred, -1.0, 0.0, &mut sharpened)?;
            gray = sharpened;
        }
    }
    if opencv::core::mean_def(&gray)?[0] < 127.0 {
        let mut inverted = Mat::default();
        opencv::core::bitwise_not_def(&gray, &mut inverted)?;
        gray = inverted;
    }
    let mut bordered = Mat::default();
    opencv::core::copy_make_border(
        &gray,
        &mut bordered,
        10,
        10,
        10,
        10,
        BORDER_CONSTANT,
        Scalar::all(255.0),
    )?;
    Ok(bordered)
}

impl OcrAnalyzer {
    /// `get_image_text`: tesseract's text of `image`, cleaned up. Err when the pass raised.
    fn image_text(
        &self,
        ctx: &TaskContext<OcrSettings>,
        image: &Mat,
        n: u32,
    ) -> Result<Result<String, String>, ModuleError> {
        let Some(scratch) = ctx.scratch_dir() else {
            return Err(ModuleError::other(
                "ocr needs a scratch directory for tesseract",
            ));
        };
        let mut png = Vector::<u8>::new();
        if !imgcodecs::imencode_def(".png", image, &mut png).map_err(cv)? {
            return Ok(Err("the image didn't encode".to_owned()));
        }
        let input = scratch.join(format!("ocr-{n}.png"));
        std::fs::write(&input, png.as_slice())?;
        let input_path = input.display().to_string();
        let mut run = ToolRun::new(
            "tesseract",
            [
                input_path.as_str(),
                "output",
                "--oem",
                "1",
                "--psm",
                "3",
                "txt",
            ],
        )
        .read(&input)
        .keep("output.txt")
        .timeout(Duration::from_secs(ctx.settings().timeout));
        if let Some(limit) = ctx.settings().omp_thread_limit {
            run = run.env("OMP_THREAD_LIMIT", &limit.to_string());
        }
        let output = ctx.run_tool(run)?;
        std::fs::remove_file(&input).ok();
        match output.returncode() {
            Some(0) => {}
            Some(code) => return Ok(Err(format!("tesseract exited {code}"))),
            None => return Ok(Err("tesseract didn't finish".to_owned())),
        }
        let Some(text) = output.output("output.txt") else {
            return Ok(Err("tesseract wrote no text".to_owned()));
        };
        let bytes = std::fs::read(text)?;
        // pytesseract decodes it strictly
        match String::from_utf8(bytes) {
            Ok(text) => Ok(Ok(self.cleanup.clean(&text))),
            Err(e) => Ok(Err(e.to_string())),
        }
    }
}

impl Parser for OcrAnalyzer {
    fn analyze(&self, ctx: &TaskContext<OcrSettings>) -> Result<Outcome<OcrAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let limit = ctx.settings().file_size_limit;
        if limit > 0 && file.size > limit {
            return Ok(Outcome::Skipped("larger than file_size_limit".to_owned()));
        }
        if !is_image(&file.local_path)? {
            return Ok(Outcome::Skipped("not an image".to_owned()));
        }
        let gray = match decode_bgr(&file.local_path) {
            Ok(Some(bgr)) => luma(&bgr).map_err(cv)?,
            Ok(None) | Err(_) => {
                tracing::warn!("the image doesn't read");
                return Ok(Outcome::Skipped("the image doesn't read".to_owned()));
            }
        };
        let gray = preprocess(gray).map_err(cv)?;
        let mut texts: Vec<(&str, String)> = Vec::new();
        let mut failed = false;
        match self.image_text(ctx, &gray, 1)? {
            Ok(text) if !text.is_empty() => {
                texts.push((
                    "GRAYSCALE NO LINE BREAKS",
                    remove_line_wrapping(&text, &self.dictionary),
                ));
                texts.push(("GRAYSCALE", text));
            }
            Ok(_) => {}
            Err(why) => {
                tracing::warn!(%why, "unable to extract text from the grey image");
                failed = true;
            }
        }
        let mut denoised = Mat::default();
        photo::fast_nl_means_denoising(&gray, &mut denoised, 10.0, 7, 21).map_err(cv)?;
        match self.image_text(ctx, &denoised, 2)? {
            Ok(text) if !text.is_empty() => {
                texts.push((
                    "DENOISED NO LINE BREAKS",
                    remove_line_wrapping(&text, &self.dictionary),
                ));
                texts.push(("DENOISED", text));
            }
            Ok(_) => {}
            Err(why) => {
                tracing::warn!(%why, "unable to extract text from the denoised image");
                failed = true;
            }
        }
        if texts.is_empty() {
            if failed {
                return Ok(Outcome::Skipped("a pass failed".to_owned()));
            }
            return Ok(Outcome::Done(ResultEnvelope::new(OcrAnalysis::default())));
        }
        texts.sort_by(|a, b| a.0.cmp(b.0));
        let mut body = String::new();
        for (header, text) in &texts {
            body.push_str(&format!("===== {header} =====\n\n{text}\n\n"));
        }
        let mut result = ResultEnvelope::new(OcrAnalysis {
            error: None,
            ocr: true,
        });
        result.summary = Some("OCR Analysis".to_owned());
        let target = format!("{}.ocr/{}.ocr", file.path.as_str(), file.name());
        if name_fits(&target) {
            let mut new_file = ctx.write_file(
                &target,
                body.as_bytes(),
                &[YaraMeta::new("type", "document.text.ocr").map_err(ModuleError::other)?],
            )?;
            new_file.relationships.push(Relationship::new(
                RelationshipKind::ExtractedFrom,
                source(file),
            ));
            new_file.add_directive("extract_urls");
            new_file.add_directive("extract_urls_domain_as_url");
            new_file.redirection = Some(source(file));
            result.files.push(new_file);
        }
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// enchant's answers in ace3's container, for words tesseract's lines end in.
    #[test]
    fn the_dictionary_answers_as_enchant() {
        let read = |path: &str| std::fs::read_to_string(path).unwrap();
        let dictionary =
            spellbook::Dictionary::new(&read(DICTIONARY.0), &read(DICTIONARY.1)).unwrap();
        let answers = [
            ("today.", true),
            ("Friday.", true),
            ("don\u{2019}t", true),
            ("in,", false),
            ("e-mail", true),
            ("https://x.com", false),
            ("Indicators:", false),
            ("dash...", true),
            ("42", true),
            ("(c)", false),
            ("support@example-help.net", false),
            ("Code:", false),
            ("7731-ALPHA", true),
            ("suspended.", true),
        ];
        let wrong: Vec<_> = answers
            .iter()
            .filter(|(word, enchant)| check(&dictionary, word) != *enchant)
            .collect();
        assert!(wrong.is_empty(), "{wrong:?}");
    }

    #[test]
    fn tesseracts_misreadings_are_fixed_as_ace3_fixes_them() {
        let cleanup = Cleanup::new();
        assert_eq!(
            cleanup.clean("hiip://a.com htips//b"),
            "http://a.com http://b"
        );
        assert_eq!(cleanup.clean("x@yl. Jcom"), "x@y[.]com");
        assert_eq!(
            cleanup.clean("evil{.}example f.Jcom"),
            "evil[.]example [.]com"
        );
        assert_eq!(cleanup.clean("“quoted” — a…"), "\"quoted\" - a...");
        assert_eq!(cleanup.clean("[.]abcl.Jcom"), "[.]abc[.]com");
    }
}
