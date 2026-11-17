//! `pdf_link_text`, a port of ace3's `PDFLinkTextAnalyzer` (`saq/modules/file_analysis/pdf.py`): the
//! text a PDF shows under each of its links, which the lure module reads as the links' text.
//!
//! ace3 reads the link annotations with pikepdf and has poppler's `pdftotext -bbox` place the words
//! of the pages with links, in its tool sandbox. Here libqpdf reads the annotations in the task's own
//! process (`crate::objects`, as the PDF module's annotation URIs), and `pdftotext` runs in the
//! sandbox runner (PLAN.md 7.3), so the module is on the sandbox pool.
//!
//! A link's text is the words whose centre is inside its `/Rect`, and its line the words of the
//! lines that box is on. A link with nothing under it keeps the annotation's `/Contents`, which is
//! all a link past `link_text_pages`, on a rotated page or without a `/Rect` gets.
//!
//! What bounds it, as in ace3: each (URL, page, box) is recorded once and at most `max_links` of
//! them, because a PDF can repeat one annotation object without limit; a page of more than
//! `max_page_words` words isn't placed; a link whose lines hold more than `max_link_band_words`
//! words covers a page, not a line, and gets no text; and pdftotext has 10 seconds and the runner's
//! 64 MiB of output. `docs/measurements/pdf-link-text.md` has crafted files against those.
//!
//! When pdftotext doesn't finish or exits non-zero the result is marked failed with the reason
//! (`ResultEnvelope::error`, ace3's `Analysis.error`), and the links are kept without their text.

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::sync::LazyLock;
use std::time::Duration;

use ace_pycompat::pystr;
use ace_results::types::pdf::{PdfLink, PdfLinkTextAnalysis};
use ace_results::{ObservableKind, ResultEnvelope};
use ace_sdk::tools::{ToolOutput, ToolRun};
use ace_sdk::{InputFile, Manifest, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use regex::Regex;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::objects::{Objects, Py, decimal_turns_the_page};
use crate::qpdf::{Document, Raised};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<PdfLinkTextAnalyzer>();

const DISPLAY_NAME: &str = "PDF Link Text Analysis";
/// ace3's `PDFTOTEXT_TIMEOUT_SECONDS`.
const PDFTOTEXT_TIMEOUT: Duration = Duration::from_secs(10);
/// ace3's `LINK_TEXT_MAX_LEN`.
const LINK_TEXT_MAX_LEN: usize = 200;
/// ace3's `LINK_BOX_TOLERANCE`: how far, in points, a word's centre may be outside a link's box and
/// still count as under it.
const LINK_BOX_TOLERANCE: f64 = 2.0;
/// How much of pdftotext's stderr a failure's reason keeps: `tool_failure_reason`'s 500.
const REASON_MAX_LEN: usize = 500;

/// ace3's `BBOX_TOKEN_PATTERN`.
static BBOX_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)(?P<page><page )|<word xMin="(-?[\d.]+)" yMin="(-?[\d.]+)" xMax="(-?[\d.]+)" yMax="(-?[\d.]+)">(.*?)</word>"#,
    )
    .expect("the pattern compiles")
});

/// ace3's section of the module, but for `pdftotext_path`, which the pool's image names, and
/// `cache_ttl`, which is of ace3's analysis result cache.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct PdfLinkTextSettings {
    /// How many link annotations per PDF are recorded. At least 1.
    pub max_links: usize,
    /// Only the links on the first this many pages get the text under them. At least 1.
    pub link_text_pages: i64,
    /// A page of more words than this isn't placed, and its links get no text. At least 1.
    pub max_page_words: usize,
    /// A link whose lines hold more words than this, across the page, covers a page, not a line,
    /// and gets no text. At least 1.
    pub max_link_band_words: usize,
}

impl Default for PdfLinkTextSettings {
    /// ace3's `saq.default.yaml`.
    fn default() -> Self {
        PdfLinkTextSettings {
            max_links: 200,
            link_text_pages: 3,
            max_page_words: 20_000,
            max_link_band_words: 500,
        }
    }
}

/// The link text module.
pub struct PdfLinkTextAnalyzer;

impl Module for PdfLinkTextAnalyzer {
    const NAME: &'static str = "pdf_link_text";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const TOOLS: &'static [&'static str] = &["pdftotext"];
    // libqpdf reads the file here, as in the PDF module, whose memory it gets
    // (`docs/measurements/pdf-hostile.md`); pdftotext has ten of these seconds.
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        memory_mb: 2048,
        cpu_seconds: 60,
    };
    type Output = PdfLinkTextAnalysis;
    type Settings = PdfLinkTextSettings;

    fn init(settings: &PdfLinkTextSettings) -> Result<Self, ModuleError> {
        // ace3's `Field(ge=1)` on each
        for (name, value) in [
            ("max_links", settings.max_links > 0),
            ("link_text_pages", settings.link_text_pages > 0),
            ("max_page_words", settings.max_page_words > 0),
            ("max_link_band_words", settings.max_link_band_words > 0),
        ] {
            if !value {
                return Err(ModuleError::other(format!("{name} must be at least 1")));
            }
        }
        Ok(PdfLinkTextAnalyzer)
    }
}

/// A link annotation as ace3's `read_links` keeps it until its text is placed.
#[derive(Debug, Clone, PartialEq)]
pub struct Link {
    pub url: String,
    pub page: i64,
    /// The annotation's `/Rect`, when it is four numbers.
    pub rect: Option<[f64; 4]>,
    /// pdftotext places the words of a rotated page in the rotated frame.
    pub rotated: bool,
    pub mediabox: [f64; 4],
    /// The annotation's `/Contents` until the text under the link is placed.
    pub text: Option<String>,
    pub line: Option<String>,
}

/// `str[:n]`, by characters.
fn chars_prefix(text: &str, n: usize) -> &str {
    match text.char_indices().nth(n) {
        Some((at, _)) => &text[..at],
        None => text,
    }
}

/// `_annotation_rect`: the annotation's `/Rect` as four floats. None for no `/Rect` or one that isn't
/// numbers, which is what raises `TypeError` or `ValueError` in ace3; anything else it raises ends
/// the read.
fn annotation_rect(objects: &Objects<'_>, annot: &Py) -> Result<Option<[f64; 4]>, Raised> {
    let rect = objects.get(annot, "/Rect")?;
    let items = objects.items(&rect);
    let read = |items: &[Py]| -> Result<Vec<f64>, Raised> {
        items.iter().map(|item| objects.float(item)).collect()
    };
    let values = match &items {
        Ok(items) => read(items),
        Err(raised) => Err(raised.clone()),
    };
    // a PDF can repeat one annotation without limit, and libqpdf keeps a handle until it's given
    // back
    for item in items.iter().flatten() {
        objects.release(item);
    }
    objects.release(&rect);
    match values {
        Ok(values) => Ok(<[f64; 4]>::try_from(values).ok()),
        Err(raised) if matches!(raised.kind.as_str(), "TypeError" | "ValueError") => Ok(None),
        Err(raised) => Err(raised),
    }
}

/// `_annotation_contents`: `str(annot.get('/Contents')).strip()[:200] or None`.
fn annotation_contents(objects: &Objects<'_>, annot: &Py) -> Result<Option<String>, Raised> {
    let contents = objects.get(annot, "/Contents")?;
    if matches!(contents, Py::None) {
        return Ok(None);
    }
    let text = objects.text(&contents);
    objects.release(&contents);
    let text = text?;
    let text = chars_prefix(pystr::strip(&text), LINK_TEXT_MAX_LEN);
    Ok((!text.is_empty()).then(|| text.to_owned()))
}

/// `bool(int(page.get("/Rotate", 0)) % 360)`.
fn rotated(objects: &Objects<'_>, page: &Py) -> Result<bool, Raised> {
    Ok(match objects.get(page, "/Rotate")? {
        Py::None => false,
        Py::Bool(value) => value,
        Py::Int(value) => value % 360 != 0,
        Py::Decimal(text) => decimal_turns_the_page(&text),
        Py::Object(_) => return Err(Raised::new("TypeError", "Object is not numeric")),
        Py::Str(_) | Py::EmptyList => false,
    })
}

/// A `(URL, page, box)`, which ace3 records once: a float by its bits, but for the zeros, which
/// Python holds equal, and a NaN, which no box read from a file is.
type LinkKey = (String, i64, Option<[u64; 4]>);

fn link_key(url: &str, page: i64, rect: Option<[f64; 4]>) -> LinkKey {
    let bits = |value: f64| if value == 0.0 { 0 } else { value.to_bits() };
    (url.to_owned(), page, rect.map(|r| r.map(bits)))
}

/// `read_links`: the PDF's link annotations, each (URL, page, box) once and at most `max_links` of
/// them, and whether there were more.
pub fn read_links(objects: &Objects<'_>, max_links: usize) -> Result<(Vec<Link>, bool), Raised> {
    let mut links = Vec::new();
    let mut seen: HashSet<LinkKey> = HashSet::new();
    let mut truncated = false;
    objects.each_uri_annotation(|found| {
        let url = objects.text(&found.uri)?;
        let page = i64::from(found.page_number);
        let rect = annotation_rect(objects, &found.annot)?;
        let key = link_key(&url, page, rect);
        if seen.contains(&key) {
            return Ok(true);
        }
        if links.len() >= max_links {
            truncated = true;
            return Ok(true);
        }
        seen.insert(key);
        links.push(Link {
            url,
            page,
            rect,
            rotated: rotated(objects, &found.page)?,
            mediabox: objects.mediabox(&found.page)?,
            text: annotation_contents(objects, &found.annot)?,
            line: None,
        });
        Ok(true)
    })?;
    Ok((links, truncated))
}

/// A word of `pdftotext -bbox`: (xMin, yMin, xMax, yMax, text).
pub type Word = (f64, f64, f64, f64, String);

/// Why the words couldn't be read: what ace3's `float()` raises on a coordinate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadCoordinate(pub String);

/// `float(text)` of what the pattern's `-?[\d.]+` matched: Python reads any decimal digit, as the
/// pattern matches one.
fn coordinate(text: &str) -> Result<f64, BadCoordinate> {
    let mut ascii = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii() {
            ascii.push(c);
        } else {
            // the decimal digits of a script are ten in a row, from its zero
            let mut zero = c;
            while let Some(before) = char::from_u32(zero as u32 - 1)
                && pystr::is_decimal(before)
            {
                zero = before;
            }
            ascii.push(char::from(b'0' + ((c as u32 - zero as u32) % 10) as u8));
        }
    }
    ascii
        .parse::<f64>()
        .map_err(|_| BadCoordinate(text.to_owned()))
}

/// What `parse_bbox_words` reads: the words of each page that is placed, by its number, and the
/// numbers of the pages with too many words.
pub type PlacedPages = (BTreeMap<i64, Vec<Word>>, Vec<i64>);

/// `parse_bbox_words`: the words of `pdftotext -bbox` output by page number, and the pages of more
/// than `max_words` words, which are left out so a page of tiny print doesn't fill the task's
/// memory.
pub fn parse_bbox_words(
    output: &str,
    first_page: i64,
    max_words: usize,
) -> Result<PlacedPages, BadCoordinate> {
    let mut pages: BTreeMap<i64, Vec<Word>> = BTreeMap::new();
    let mut page = first_page - 1;
    let mut started = false;
    for found in BBOX_TOKEN.captures_iter(output) {
        if found.name("page").is_some() {
            page += 1;
            started = true;
            // a dict assignment: a page of the same number starts again, which no output has
            pages.insert(page, Vec::new());
            continue;
        }
        if !started {
            continue;
        }
        let Some(words) = pages.get_mut(&page) else {
            continue;
        };
        if words.len() > max_words {
            continue;
        }
        let group = |i: usize| found.get(i).map_or("", |m| m.as_str());
        words.push((
            coordinate(group(2))?,
            coordinate(group(3))?,
            coordinate(group(4))?,
            coordinate(group(5))?,
            ace_pycompat::html::unescape(group(6)).into_owned(),
        ));
    }
    let crowded = pages
        .iter()
        .filter(|(_, words)| words.len() > max_words)
        .map(|(number, _)| *number)
        .collect();
    pages.retain(|_, words| words.len() <= max_words);
    Ok((pages, crowded))
}

/// A page's words sorted by the y of their centre, with those centres, each word with its place in
/// reading order: ace3's `WordIndex`.
pub struct WordIndex<'w> {
    centers: Vec<f64>,
    entries: Vec<(usize, &'w Word)>,
}

/// `index_words`.
pub fn index_words(words: &[Word]) -> WordIndex<'_> {
    let center = |word: &Word| (word.1 + word.3) / 2.0;
    let mut entries: Vec<(usize, &Word)> = words.iter().enumerate().collect();
    // Python's sort is stable, and a coordinate pdftotext wrote is never a NaN
    entries.sort_by(|a, b| {
        center(a.1)
            .partial_cmp(&center(b.1))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    WordIndex {
        centers: entries.iter().map(|(_, word)| center(word)).collect(),
        entries,
    }
}

/// Python's `min(a, b)` and `max(a, b)` of two floats, which keep the first unless the second
/// compares below or above it, so a NaN stays where it is.
fn py_min(a: f64, b: f64) -> f64 {
    if b < a { b } else { a }
}

fn py_max(a: f64, b: f64) -> f64 {
    if b > a { b } else { a }
}

/// `bisect.bisect_left` and `bisect.bisect_right`, by their own comparisons.
fn bisect_left(sorted: &[f64], x: f64) -> usize {
    let (mut low, mut high) = (0, sorted.len());
    while low < high {
        let middle = (low + high) / 2;
        if sorted[middle] < x {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    low
}

fn bisect_right(sorted: &[f64], x: f64) -> usize {
    let (mut low, mut high) = (0, sorted.len());
    while low < high {
        let middle = (low + high) / 2;
        if x < sorted[middle] {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    low
}

/// `" ".join(words)[:200] or None`.
fn joined(words: &[&str]) -> Option<String> {
    let text = words.join(" ");
    let text = chars_prefix(&text, LINK_TEXT_MAX_LEN);
    (!text.is_empty()).then(|| text.to_owned())
}

/// `link_text`: the text under a link annotation's box and the text of the line it is on; none when
/// the lines the box is on hold more than `max_words` words across the page, which makes it a page
/// rather than a line. `rect` and `mediabox` are in PDF space, from the bottom left; pdftotext
/// places words from the media box's top left.
pub fn link_text(
    rect: [f64; 4],
    mediabox: [f64; 4],
    index: &WordIndex<'_>,
    max_words: usize,
) -> (Option<String>, Option<String>) {
    let page_left = py_min(mediabox[0], mediabox[2]);
    let page_top = py_max(mediabox[1], mediabox[3]);
    let left = py_min(rect[0], rect[2]) - page_left;
    let right = py_max(rect[0], rect[2]) - page_left;
    let top = page_top - py_max(rect[1], rect[3]);
    let bottom = page_top - py_min(rect[1], rect[3]);
    let low = bisect_left(&index.centers, top - LINK_BOX_TOLERANCE);
    let high = bisect_right(&index.centers, bottom + LINK_BOX_TOLERANCE);
    if high > low && high - low > max_words {
        return (None, None);
    }
    let mut band: Vec<(usize, &Word)> = index
        .entries
        .get(low..high)
        .map(<[_]>::to_vec)
        .unwrap_or_default();
    band.sort_by_key(|(place, _)| *place);
    let mut under = Vec::new();
    let mut line = Vec::new();
    for (_, word) in band {
        line.push(word.4.as_str());
        let center = (word.0 + word.2) / 2.0;
        if left - LINK_BOX_TOLERANCE <= center && center <= right + LINK_BOX_TOLERANCE {
            under.push(word.4.as_str());
        }
    }
    (joined(&under), joined(&line))
}

/// `tool_failure_reason`: how pdftotext exited, and the last line of its stderr.
fn failure_reason(returncode: i32, stderr: &str) -> String {
    // 128 + N is a command killed by signal N; Linux's SIGRTMAX is 64
    let mut reason = if (129..=128 + 64).contains(&returncode) {
        format!("pdftotext was killed by signal {}", returncode - 128)
    } else {
        format!("pdftotext exited with status {returncode}")
    };
    if let Some(last) = pystr::splitlines(pystr::strip(stderr)).last() {
        reason.push_str(": ");
        reason.push_str(chars_prefix(last, REASON_MAX_LEN));
    }
    reason
}

/// What `place_link_text` does with pdftotext's run: sets the text under each placeable link, where
/// there is any, and its line. Returns why pdftotext's words weren't used, or None.
pub fn place_words(
    links: &mut [Link],
    placeable: &[usize],
    first_page: i64,
    output: &ToolOutput,
    settings: &PdfLinkTextSettings,
) -> Option<String> {
    let Some(returncode) = output.returncode() else {
        return Some("pdftotext did not finish".to_owned());
    };
    if returncode != 0 {
        return Some(failure_reason(returncode, &output.stderr_text()));
    }
    let text = output.stdout_text();
    let (pages, crowded) = match parse_bbox_words(&text, first_page, settings.max_page_words) {
        Ok(parsed) => parsed,
        // ace3's float() raises, and its module catches it around the whole placement
        Err(BadCoordinate(_)) => return Some("placing the link text raised ValueError".to_owned()),
    };
    if !crowded.is_empty() {
        tracing::info!(
            pages = ?crowded,
            max_page_words = settings.max_page_words,
            "pages have too many words to place; their links get no text"
        );
    }
    let indexes: BTreeMap<i64, WordIndex<'_>> = pages
        .iter()
        .map(|(number, words)| (*number, index_words(words)))
        .collect();
    for &at in placeable {
        let link = &mut links[at];
        let (Some(index), Some(rect)) = (indexes.get(&link.page), link.rect) else {
            continue;
        };
        let (text, line) = link_text(rect, link.mediabox, index, settings.max_link_band_words);
        if text.is_some() {
            link.text = text;
        }
        link.line = line;
    }
    None
}

/// The links of `place_link_text` that can be placed: those with a box, on a page that isn't
/// rotated, among the first `link_text_pages`.
pub fn placeable(links: &[Link], link_text_pages: i64) -> Vec<usize> {
    links
        .iter()
        .enumerate()
        .filter(|(_, link)| link.rect.is_some() && !link.rotated && link.page <= link_text_pages)
        .map(|(at, _)| at)
        .collect()
}

/// `PDFLinkTextAnalysis.generate_summary`.
pub fn summary(links: &[PdfLink]) -> String {
    let placed = links
        .iter()
        .filter(|link| {
            link.text.as_deref().is_some_and(|t| !t.is_empty())
                || link.line.as_deref().is_some_and(|l| !l.is_empty())
        })
        .count();
    format!("{DISPLAY_NAME}: {} links, {placed} with text", links.len())
}

/// The links of the PDF at `path`, as ace3's `pikepdf.open` and `read_links`.
pub fn links_of(path: &std::path::Path, max_links: usize) -> Result<(Vec<Link>, bool), Raised> {
    let document = Document::open(path)?;
    let objects = Objects {
        document: &document,
    };
    read_links(&objects, max_links)
}

fn looks_like_pdf(file: &InputFile) -> std::io::Result<bool> {
    // ace3's is_pdf_file: not the PDF module's own dump, and `%PDF-` in the first 1024 bytes
    if file.path.as_str().ends_with(".pdfparser") {
        return Ok(false);
    }
    let mut head = Vec::with_capacity(1024);
    File::open(&file.local_path)?
        .take(1024)
        .read_to_end(&mut head)?;
    Ok(head.windows(5).any(|w| w == b"%PDF-"))
}

impl Parser for PdfLinkTextAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<PdfLinkTextSettings>,
    ) -> Result<Outcome<PdfLinkTextAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        if !looks_like_pdf(file)? {
            return Ok(Outcome::Skipped("not a PDF".to_owned()));
        }
        let settings = ctx.settings();
        let (mut links, truncated) = match links_of(&file.local_path, settings.max_links) {
            Ok(read) => read,
            // a damaged or password protected PDF is the sender's doing; pdf_analyzer reports what
            // it can read
            Err(raised) => {
                tracing::warn!(%raised, "cannot read the PDF's links");
                return Ok(Outcome::Skipped("the PDF's links can't be read".to_owned()));
            }
        };
        if links.is_empty() {
            return Ok(Outcome::Skipped("the PDF has no links".to_owned()));
        }
        if truncated {
            tracing::info!(
                max_links = settings.max_links,
                "the PDF has more links than are recorded"
            );
        }
        ctx.check_cancelled()?;

        let mut error = None;
        let placeable = placeable(&links, settings.link_text_pages);
        if let (Some(first), Some(last)) = (
            placeable.iter().map(|&at| links[at].page).min(),
            placeable.iter().map(|&at| links[at].page).max(),
        ) {
            let local = file.local_path.display().to_string();
            let run = ToolRun::new(
                "pdftotext",
                [
                    "-bbox",
                    "-f",
                    &first.to_string(),
                    "-l",
                    &last.to_string(),
                    local.as_str(),
                    "-",
                ],
            )
            .read(&file.local_path)
            .timeout(PDFTOTEXT_TIMEOUT);
            let output = ctx.run_tool(run)?;
            if let Some(failure) = place_words(&mut links, &placeable, first, &output, settings) {
                // the links are kept without the text under them, as ace3 keeps them
                let failure = format!("{failure}, without the text under the links");
                tracing::warn!(stopped = ?output.stopped(), "{failure}");
                error = Some(failure);
            }
        }

        let links: Vec<PdfLink> = links
            .into_iter()
            .map(|link| PdfLink {
                url: link.url,
                page: link.page,
                text: link.text,
                line: link.line,
            })
            .collect();
        let summary = summary(&links);
        let mut result = ResultEnvelope::new(PdfLinkTextAnalysis { links }).with_summary(summary);
        result.error = error;
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(x0: f64, y0: f64, x1: f64, y1: f64, text: &str) -> Word {
        (x0, y0, x1, y1, text.to_owned())
    }

    const PAGE: &str = r#"<doc>
  <page width="200.000000" height="200.000000">
    <word xMin="10.000000" yMin="20.000000" xMax="40.000000" yMax="30.000000">Click</word>
    <word xMin="45.000000" yMin="20.000000" xMax="70.000000" yMax="30.000000">here</word>
    <word xMin="75.000000" yMin="20.000000" xMax="120.000000" yMax="30.000000">to &amp; fro</word>
    <word xMin="10.000000" yMin="100.000000" xMax="60.000000" yMax="110.000000">Unrelated</word>
  </page>
  <page width="200.000000" height="200.000000">
    <word xMin="-1.5" yMin="0" xMax="1." yMax=".5">second</word>
  </page>
</doc>"#;

    #[test]
    fn words_are_read_by_page_from_the_first_page_asked_for() {
        let (pages, crowded) = parse_bbox_words(PAGE, 2, 10).expect("parses");
        assert!(crowded.is_empty());
        assert_eq!(pages.keys().copied().collect::<Vec<_>>(), [2, 3]);
        assert_eq!(pages[&2].len(), 4);
        assert_eq!(pages[&2][2].4, "to & fro");
        assert_eq!(pages[&3][0], word(-1.5, 0.0, 1.0, 0.5, "second"));
    }

    #[test]
    fn a_word_before_any_page_is_dropped_and_a_crowded_page_left_out() {
        let output = format!(
            "<word xMin=\"1\" yMin=\"1\" xMax=\"2\" yMax=\"2\">stray</word>{}",
            PAGE
        );
        let (pages, crowded) = parse_bbox_words(&output, 1, 3).expect("parses");
        assert_eq!(crowded, [1]);
        assert_eq!(pages.keys().copied().collect::<Vec<_>>(), [2]);
    }

    #[test]
    fn a_coordinate_python_cannot_read_is_an_error_and_other_digits_are_read() {
        let bad = "<page ><word xMin=\"1.2.3\" yMin=\"1\" xMax=\"2\" yMax=\"2\">x</word>";
        assert_eq!(
            parse_bbox_words(bad, 1, 10),
            Err(BadCoordinate("1.2.3".to_owned()))
        );
        // Arabic-Indic and mathematical digits, which Python's \d matches and float() reads
        assert_eq!(coordinate("\u{661}\u{662}.\u{665}"), Ok(12.5));
        assert_eq!(coordinate("-\u{1d7d7}"), Ok(-9.0));
        assert_eq!(coordinate("-\u{1d7d8}"), Ok(-0.0));
        assert!(coordinate(".").is_err());
    }

    #[test]
    fn a_link_gets_the_words_under_it_and_its_line() {
        let (pages, _) = parse_bbox_words(PAGE, 1, 10).expect("parses");
        let index = index_words(&pages[&1]);
        // PDF space is from the bottom left: y 170 to 180 is 20 to 30 from the top of a 200 page
        let (text, line) = link_text(
            [8.0, 170.0, 72.0, 180.0],
            [0.0, 0.0, 200.0, 200.0],
            &index,
            500,
        );
        assert_eq!(text.as_deref(), Some("Click here"));
        assert_eq!(line.as_deref(), Some("Click here to & fro"));
        // the box turned around, and a media box that doesn't start at the origin
        let (text, _) = link_text(
            [172.0, 280.0, 108.0, 270.0],
            [100.0, 100.0, 300.0, 300.0],
            &index,
            500,
        );
        assert_eq!(text.as_deref(), Some("Click here"));
        // a box over nothing has its line's text only when a line is there
        let (text, line) = link_text(
            [150.0, 170.0, 190.0, 180.0],
            [0.0, 0.0, 200.0, 200.0],
            &index,
            500,
        );
        assert_eq!((text, line.as_deref()), (None, Some("Click here to & fro")));
        let (text, line) = link_text(
            [0.0, 0.0, 10.0, 10.0],
            [0.0, 0.0, 200.0, 200.0],
            &index,
            500,
        );
        assert_eq!((text, line), (None, None));
    }

    #[test]
    fn a_box_over_too_many_words_is_a_page_and_gets_nothing() {
        let (pages, _) = parse_bbox_words(PAGE, 1, 10).expect("parses");
        let index = index_words(&pages[&1]);
        let whole = [0.0, 0.0, 200.0, 200.0];
        assert_eq!(link_text(whole, whole, &index, 3), (None, None));
        let (text, _) = link_text(whole, whole, &index, 4);
        assert_eq!(text.as_deref(), Some("Click here to & fro Unrelated"));
    }

    #[test]
    fn a_box_that_is_not_finite_matches_as_pythons_comparisons_do() {
        let (pages, _) = parse_bbox_words(PAGE, 1, 10).expect("parses");
        let index = index_words(&pages[&1]);
        let page = [0.0, 0.0, 200.0, 200.0];
        // inf - inf is a NaN: bisect_left gives 0 and bisect_right the end, and no centre is
        // between two NaNs
        let (text, line) = link_text(
            [f64::INFINITY, f64::INFINITY, f64::INFINITY, f64::INFINITY],
            [0.0, 0.0, f64::INFINITY, f64::INFINITY],
            &index,
            500,
        );
        assert_eq!(text, None);
        assert_eq!(line.as_deref(), Some("Click here to & fro Unrelated"));
        assert_eq!(
            link_text([0.0, f64::NAN, 10.0, 0.0], page, &index, 3),
            (None, None)
        );
    }

    #[test]
    fn text_is_cut_at_200_characters() {
        let words: Vec<Word> = (0..60)
            .map(|i| word(f64::from(i), 0.0, f64::from(i) + 1.0, 10.0, "wörd"))
            .collect();
        let index = index_words(&words);
        let (text, _) = link_text(
            [0.0, 0.0, 100.0, 10.0],
            [0.0, 0.0, 100.0, 10.0],
            &index,
            500,
        );
        assert_eq!(text.expect("text").chars().count(), 200);
    }

    #[test]
    fn a_failure_names_how_pdftotext_exited_and_its_last_line() {
        assert_eq!(
            failure_reason(
                1,
                "Syntax Warning: x\nSyntax Error: Couldn't read xref table\n"
            ),
            "pdftotext exited with status 1: Syntax Error: Couldn't read xref table"
        );
        assert_eq!(failure_reason(139, ""), "pdftotext was killed by signal 11");
        assert_eq!(failure_reason(99, "  "), "pdftotext exited with status 99");
    }

    #[test]
    fn a_rotation_is_counted_as_python_counts_it() {
        assert!(decimal_turns_the_page(b"90.5"));
        assert!(!decimal_turns_the_page(b"0.5"));
        assert!(!decimal_turns_the_page(b"-0.5"));
        assert!(decimal_turns_the_page(b"359.9"));
        assert!(!decimal_turns_the_page(b"360.5"));
        assert!(decimal_turns_the_page(b"99999999999999999999.5"));
        assert!(!decimal_turns_the_page(b"+720."));
        assert!(!decimal_turns_the_page(b".5"));
    }

    #[test]
    fn the_summary_counts_the_links_with_text() {
        let link = |text: Option<&str>, line: Option<&str>| PdfLink {
            url: "https://example.com/".to_owned(),
            page: 1,
            text: text.map(str::to_owned),
            line: line.map(str::to_owned),
        };
        assert_eq!(
            summary(&[
                link(Some("a"), None),
                link(None, Some("b")),
                link(None, None)
            ]),
            "PDF Link Text Analysis: 3 links, 2 with text"
        );
    }
}
