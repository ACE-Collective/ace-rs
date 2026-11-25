//! `lure_url_analyzer`, a port of ace3's `LureURLAnalyzer` (`saq/modules/email/lure.py`): which of an
//! email's URLs it lures its recipient to.
//!
//! ace3 waits for its final analysis, walks the email's subtree for the URLs it carries, recording
//! where each came from (a body part, an attachment, a QR code, a protected URL's wrapper, a PDF's
//! link annotations), reads its bodies line by line, as a mail client lays them out, for each link's
//! text and where it is in the thread (a signature block, an earlier message the email quotes),
//! takes the text a PDF shows under its links from `pdf_link_text`, scores each URL on those signals
//! and its settings' keywords and domains, and adds `crawl` to the best. Here the module runs last
//! (`Module::RUNS_LAST`) and walks the tree the core sends (`Module::READS_TREE`), with the email's
//! bodies, HTML and plain text (`Module::READS_TREE_FILES`), and the link text module's details
//! (`Module::READS_TREE_DETAILS`).
//!
//! ace3 reads its settings from `etc/lure_url.yaml`, which analysts edit and it reloads. Here they're
//! the module's settings, in the site's overlay, with the same keys and ace3's built-in values as
//! their defaults.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;

use ace_lxml::soup::{AttrValue, Node, StringKind, Tree};
use ace_pycompat::parse::{parse_qsl, urlparse};
use ace_pycompat::pystr;
use ace_results::types::email::{EmailAnalysis, EmailPart};
use ace_results::types::emailtree::{LureCandidate, LureUrlAnalysis};
use ace_results::types::pdf::PdfLinkTextAnalysis;
use ace_results::{AnalysisType, ObservableKind, ObservableRef, OtherAdditions, ResultEnvelope};
use ace_sdk::tree::{TreeFiles, TreeView};
use ace_sdk::{Manifest, Module, ModuleError, OtherAdditionsAllowed, Outcome, Parser, TaskContext};
use ace_urlfinder::url::Url;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<LureUrlAnalyzer>();

const DISPLAY_NAME: &str = "Lure URL Analysis";

const SOURCE_BODY: &str = "body";
const SOURCE_QR: &str = "qr";
const SOURCE_ATTACHMENT: &str = "attachment";

/// The files read with the tree: the email's body parts are its unnamed text parts, which the email
/// module names with these (its result records which are, and a result made before that is read by
/// these names, as ace3's `_BODY_PART_MARKERS`).
const BODY_PART_MARKERS: [&str; 2] = ["unknown_text_html", "unknown_text_plain"];
const NON_PART_YARA_TYPES: [&str; 2] = ["email.headers", "email.combined"];
/// The PDF module writes a PDF's link annotations, the PDF's `<a href>`, to a file of this type.
const PDF_LINK_ANNOTATIONS_YARA_TYPE: &str = "document.pdf.annotation_uris";

/// A body larger than this isn't parsed for its anchors.
pub const MAX_BODY_BYTES: u64 = 5 * 1024 * 1024;
const ANCHOR_TEXT_MAX_LEN: usize = 100;
/// `phishkit_chain.DISPLAY_URL_MAX_LEN`.
const DISPLAY_URL_MAX_LEN: usize = 100;

const STATIC_EXTENSIONS: [&str; 14] = [
    ".png", ".gif", ".jpg", ".jpeg", ".bmp", ".svg", ".ico", ".webp", ".tiff", ".css", ".woff",
    ".woff2", ".ttf", ".eot",
];

/// The results whose observables come after the click (the crawl's) or belong to another email's
/// lure, by module, and the one whose URLs are a QR code's: ace3's `PhishkitAnalysis`,
/// `QRCodeAnalysis`.
const PHISHKIT: &str = "phishkit_analyzer";
const QRCODE: &str = "qrcode";
/// ace3's `ProtectedURLAnalysis`, which the 1drv.ms instance writes under a type of its own.
const PROTECTED: [&str; 2] = ["protected_url_analysis", "protected_url_one_drive_analysis"];

const CRAWL: &str = "crawl";

/// A line longer than this isn't a sign-off.
const SIGN_OFF_MAX_LEN: usize = 80;
/// What follows a sign-off phrase on its line is a name of at most this many words.
const SIGN_OFF_NAME_WORDS: usize = 4;
/// How much of the newest message's text is kept to look for a reference to the attachment.
const MAX_NEWEST_TEXT: usize = 20_000;
/// The containers mail clients put an earlier, quoted message of a thread in (Gmail, Yahoo,
/// Thunderbird).
const QUOTE_CLASS_PREFIXES: [&str; 3] = ["gmail_quote", "yahoo_quoted", "moz-cite-prefix"];
/// How many lines after its `From:` line a reply header's other fields can be.
const MAX_HEADER_LINES: usize = 8;
const LINK_TAGS: [&str; 3] = ["a", "area", "form"];
/// The elements that start or end a line where a mail client renders them.
const LINE_BREAK_TAGS: [&str; 35] = [
    "address",
    "article",
    "blockquote",
    "body",
    "br",
    "caption",
    "center",
    "dd",
    "div",
    "dl",
    "dt",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "html",
    "li",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "tr",
    "ul",
];
/// The elements whose text is never shown.
const TEXT_SKIP_PARENTS: [&str; 4] = ["script", "style", "head", "title"];
const URL_TOKEN_PUNCTUATION: &str = "<>()[]\"'.,;";
const SENTENCE_ENDS: [char; 4] = ['.', '?', '!', ':'];

/// ace3's `QUOTE_MARKER_PATTERN`: the line that starts an earlier message of a thread, other than a
/// reply header. A line has single spaces only by the time it's matched.
static QUOTE_MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^(-{2,} ?(original message|forwarded message) ?-{2,}|begin forwarded message:?|on .{1,200} wrote:)$",
    )
    .expect("the pattern compiles")
});
/// ace3's `HEADER_FIELD_PATTERN`: a field of the header Outlook writes above an earlier message.
static HEADER_FIELD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(from|sent|date|to|cc|subject):").expect("compiles"));

/// ace3's `LureURLWeights`: what each signal adds to or takes from a candidate's score.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct LureWeights {
    pub qr: i64,
    pub body: i64,
    pub attachment: i64,
    pub attachment_reference: i64,
    pub clickable: i64,
    pub button: i64,
    pub call_to_action: i64,
    pub only_domain: i64,
    pub only_link: i64,
    pub unwrapped: i64,
    pub detection: i64,
    pub not_a_link: i64,
    pub signature_block: i64,
    pub quoted_message: i64,
    pub sender_domain: i64,
    pub noise: i64,
    #[serde(rename = "static")]
    pub static_: i64,
    pub benign: i64,
}

impl Default for LureWeights {
    fn default() -> Self {
        LureWeights {
            qr: 35,
            body: 20,
            attachment: 15,
            attachment_reference: 20,
            clickable: 25,
            button: 15,
            call_to_action: 20,
            only_domain: 10,
            only_link: 10,
            unwrapped: 5,
            detection: 30,
            not_a_link: -15,
            signature_block: -25,
            // 0 because a phish forwarded inline has its lure in the part it quotes
            quoted_message: 0,
            sender_domain: -20,
            noise: -30,
            static_: -40,
            benign: -50,
        }
    }
}

/// ace3's `LureURLSettings`, `etc/lure_url.yaml`'s keys. A key left with nothing under it is an
/// empty list, or for `weights` the defaults, as ace3's validators read one.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct LureSettings {
    /// Anchor text words that ask the recipient to click.
    #[serde(deserialize_with = "null_is_default")]
    pub call_to_action_keywords: Vec<String>,
    /// Words in a link or its text that mark it as an unsubscribe, privacy or footer link.
    #[serde(deserialize_with = "null_is_default")]
    pub noise_keywords: Vec<String>,
    /// Domains, and their subdomains, that are never the lure.
    #[serde(deserialize_with = "null_is_default")]
    pub benign_domains: Vec<String>,
    /// Phrases in the newest message of the email, before its signature, that refer to its
    /// attachment, as whole words, whatever their case.
    #[serde(deserialize_with = "null_is_default")]
    pub attachment_reference_keywords: Vec<String>,
    /// A line that starts with one of these, then ends or goes on after a comma, ends the message's
    /// text; the signature block below it runs to the next message.
    #[serde(deserialize_with = "null_is_default")]
    pub sign_off_phrases: Vec<String>,
    /// How many ranked candidates to keep, the primary included. At least 1.
    pub max_candidates: usize,
    /// A line of more words than this is a sentence: after a sign-off, it means the sign-off wasn't
    /// one. At least 1.
    pub sentence_words: usize,
    /// A line of at least this many words that ends in `.`, `?`, `!` or `:` is a sentence too. At
    /// least 1.
    pub sentence_end_words: usize,
    /// Add the crawl directive to the primary lure URL.
    pub crawl_primary: bool,
    /// A candidate needs at least this score to be called the primary lure URL.
    pub min_primary_score: i64,
    #[serde(deserialize_with = "null_is_default")]
    pub weights: LureWeights,
}

fn null_is_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).to_owned()).collect()
}

impl Default for LureSettings {
    fn default() -> Self {
        LureSettings {
            call_to_action_keywords: strings(&[
                "view", "review", "open", "sign", "verify", "download", "access", "confirm",
                "click", "login", "log in", "update", "secure", "document", "pay", "invoice",
                "shared",
            ]),
            noise_keywords: strings(&[
                "unsubscribe",
                "privacy",
                "terms",
                "preferences",
                "opt-out",
                "optout",
                "cookie",
                "legal",
            ]),
            benign_domains: strings(&["fonts.googleapis.com", "fonts.gstatic.com"]),
            // whole phrases: "attachments" is in the external sender banners and confidentiality
            // notices on most mail
            attachment_reference_keywords: strings(&[
                "please find attached",
                "attached",
                "enclosed",
                "see attachment",
                "see the attachment",
                "open the attachment",
                "review the attachment",
            ]),
            sign_off_phrases: strings(&[
                "regards",
                "best regards",
                "kind regards",
                "warm regards",
                "respectfully",
                "sincerely",
                "thanks",
                "thank you",
                "many thanks",
                "best",
                "cheers",
                "cordially",
            ]),
            max_candidates: 5,
            sentence_words: 12,
            sentence_end_words: 8,
            crawl_primary: true,
            min_primary_score: 1,
            weights: LureWeights::default(),
        }
    }
}

/// The lure module.
pub struct LureUrlAnalyzer {
    button_style: Regex,
}

impl Module for LureUrlAnalyzer {
    const NAME: &'static str = "lure_url_analyzer";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const DEPENDS_ON: &'static [&'static str] = &[EmailAnalysis::MODULE];
    const RUNS_LAST: bool = true;
    const READS_TREE: bool = true;
    const ADDS_TO_OTHERS: Option<OtherAdditionsAllowed> = Some(OtherAdditionsAllowed {
        tags: &[],
        directives: &[CRAWL],
        detections: false,
        relationships: false,
    });
    const READS_TREE_FILES: Option<TreeFiles> = Some(TreeFiles {
        names_containing: &BODY_PART_MARKERS,
        max_size: MAX_BODY_BYTES,
        tagged: None,
    });
    const READS_TREE_DETAILS: &'static [&'static str] = &[PdfLinkTextAnalysis::MODULE];
    type Output = LureUrlAnalysis;
    type Settings = LureSettings;

    fn init(settings: &LureSettings) -> Result<Self, ModuleError> {
        // ace3's `Field(ge=1)` on each
        for (name, value) in [
            ("max_candidates", settings.max_candidates),
            ("sentence_words", settings.sentence_words),
            ("sentence_end_words", settings.sentence_end_words),
        ] {
            if value < 1 {
                return Err(ModuleError::other(format!("{name} must be at least 1")));
            }
        }
        Ok(LureUrlAnalyzer {
            button_style: Regex::new(
                r"(?i)(background(-color)?[\s\x1c-\x1f]*:|padding[\s\x1c-\x1f]*:|border-radius[\s\x1c-\x1f]*:)",
            )
            .map_err(ModuleError::other)?,
        })
    }
}

impl Parser for LureUrlAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<LureSettings>,
    ) -> Result<Outcome<LureUrlAnalysis>, ModuleError> {
        let Some(email) = ctx
            .dependency_result::<EmailAnalysis>()?
            .filter(|email| !email.is_tag_only())
        else {
            return Ok(Outcome::Skipped(
                "the file has no email analysis".to_owned(),
            ));
        };
        let tree = ctx
            .tree()
            .ok_or_else(|| ModuleError::other("the task came without its root's tree"))?;
        let index = TreeIndex::new(tree);
        let Some(email_result) = index.result_of(tree, tree.this, EmailAnalysis::NAME) else {
            return Ok(Outcome::Skipped(
                "the file has no email analysis".to_owned(),
            ));
        };
        let settings = ctx.settings();
        let mut collector = Collector::new(tree, &index, self, settings, |sha256| {
            ctx.tree_file(sha256)
                .and_then(|path| std::fs::read(path).ok())
        });
        let candidates: Vec<Candidate> = collector
            .collect(email_result, email.parts.as_deref())
            .into_iter()
            .filter(|c| is_http_url(&tree.observable(c.observable).value))
            .collect();
        if candidates.is_empty() {
            return Ok(Outcome::Skipped("no lure url candidates".to_owned()));
        }
        let mut candidates = candidates;
        score_candidates(
            tree,
            &mut candidates,
            &sender_domains(&email),
            settings,
            &collector.body_text,
        );
        candidates.sort_by(|a, b| rank_key(tree, a).cmp(&rank_key(tree, b)));
        let primary = candidates
            .first()
            .filter(|c| c.score >= settings.min_primary_score);
        let email_details = email.email.as_ref();
        let subject = email_details
            .and_then(|e| e.decoded_subject.clone().filter(|s| !s.is_empty()))
            .or_else(|| email_details.and_then(|e| e.subject.clone()));
        let analysis = LureUrlAnalysis {
            primary: primary.map(|c| c.to_details(tree)),
            candidates: candidates
                .iter()
                .take(settings.max_candidates)
                .map(|c| c.to_details(tree))
                .collect(),
            has_inner_email: collector.has_inner_email,
            subject,
        };
        let summary = summary(&analysis);
        let mut result = ResultEnvelope::new(analysis).with_summary(summary);
        if let Some(primary) = primary
            && settings.crawl_primary
        {
            let url = tree.observable(primary.observable);
            let mut additions = ace_results::ObservableAdditions::default();
            additions.add_directive(CRAWL);
            result.others.push(OtherAdditions {
                observable: ObservableRef::new(url.kind, url.value.clone()),
                additions,
            });
            tracing::info!(
                url = %url.value,
                lure_score = primary.score,
                "the email's lure url"
            );
        }
        Ok(Outcome::Done(result))
    }
}

/// `LureURLAnalysis.generate_summary`.
pub fn summary(analysis: &LureUrlAnalysis) -> String {
    match &analysis.primary {
        None => format!("{DISPLAY_NAME}: no lure URL identified"),
        Some(primary) => format!(
            "{DISPLAY_NAME}: {} ({})",
            primary.url,
            primary.reasons.join("; ")
        ),
    }
}

/// The tree's results by the observable they're on, and by what they added, so a walk doesn't scan
/// every result at each step.
struct TreeIndex {
    on: Vec<Vec<usize>>,
}

impl TreeIndex {
    fn new(tree: &TreeView) -> TreeIndex {
        let mut on = vec![Vec::new(); tree.observables.len()];
        for (i, result) in tree.results.iter().enumerate() {
            if let Some(list) = on.get_mut(result.observable) {
                list.push(i);
            }
        }
        TreeIndex { on }
    }

    fn results_on<'t>(
        &'t self,
        tree: &'t TreeView,
        observable: usize,
    ) -> impl Iterator<Item = &'t ace_sdk::tree::TreeResult> + 't {
        self.on
            .get(observable)
            .into_iter()
            .flatten()
            .map(|&i| &tree.results[i])
    }

    fn result_of(&self, tree: &TreeView, observable: usize, analysis_type: &str) -> Option<usize> {
        self.on
            .get(observable)?
            .iter()
            .copied()
            .find(|&i| tree.results[i].analysis_type == analysis_type)
    }
}

/// Where a link sits in a body, or in its PDF: its text, whether it's styled as a button, and its
/// place, the tie-break between equal scores.
#[derive(Debug, Clone, PartialEq)]
struct Anchor {
    text: String,
    button: bool,
    position: usize,
    signature: bool,
    quoted: bool,
    /// A PDF's link annotation, whose text is what the PDF shows under it.
    pdf: bool,
}

/// ace3's `ParsedBody`: a body's links, a plain text body's URLs, each with whether it's in a
/// signature block and in a quoted message, and the text of the newest message.
#[derive(Debug, Default)]
struct ParsedBody {
    anchors: HashMap<String, Anchor>,
    text_urls: HashMap<String, (bool, bool)>,
    newest_text: String,
}

/// One URL the email carries, as ace3's `Candidate`.
#[derive(Debug, Clone)]
struct Candidate {
    observable: usize,
    sources: BTreeSet<&'static str>,
    attachments: Vec<String>,
    wrapped_by: Option<String>,
    carries: Vec<String>,
    pdf_link: bool,
    in_parsed_body: bool,
    anchor: Option<Anchor>,
    signature: bool,
    quoted: bool,
    /// The PDF whose link annotation this is, and how many distinct links that PDF has.
    pdf_name: Option<String>,
    pdf_link_count: usize,
    score: i64,
    reasons: Vec<String>,
    highlights: Vec<Vec<String>>,
}

impl Candidate {
    fn new(observable: usize) -> Candidate {
        Candidate {
            observable,
            sources: BTreeSet::new(),
            attachments: Vec::new(),
            wrapped_by: None,
            carries: Vec::new(),
            pdf_link: false,
            in_parsed_body: false,
            anchor: None,
            signature: false,
            quoted: false,
            pdf_name: None,
            pdf_link_count: 0,
            score: 0,
            reasons: Vec::new(),
            highlights: Vec::new(),
        }
    }

    /// `Candidate.to_dict`, without ace3's `observable_uuid`: ace-rs's observables have no uuid, and
    /// the URL is the observable's value.
    fn to_details(&self, tree: &TreeView) -> LureCandidate {
        LureCandidate {
            url: tree.observable(self.observable).value.clone(),
            score: self.score,
            sources: self.sources.iter().map(|s| (*s).to_owned()).collect(),
            anchor_text: self.anchor.as_ref().map(|a| a.text.clone()),
            carries: self.carries.clone(),
            reasons: self.reasons.clone(),
            highlights: self.highlights.clone(),
        }
    }
}

/// `Candidate.rank_key`: the highest score first, then the earliest in the body, then the earliest
/// in a PDF, then by value.
fn rank_key<'t>(tree: &'t TreeView, c: &Candidate) -> (i64, (bool, usize), &'t str) {
    (
        -c.score,
        c.anchor
            .as_ref()
            .map_or((true, usize::MAX), |a| (a.pdf, a.position)),
        tree.observable(c.observable).value.as_str(),
    )
}

/// `normalize_url`: urlfinderlib's spelling of a URL, or the value itself.
fn normalize_url(value: &str) -> String {
    let url = Url::new(value);
    if url.value().is_empty() {
        value.to_owned()
    } else {
        url.value().to_owned()
    }
}

/// `is_http_url`.
fn is_http_url(value: &str) -> bool {
    match urlparse(value, "", true) {
        Ok(parsed) => matches!(pystr::lower(&parsed.scheme).as_ref(), "http" | "https"),
        Err(_) => false,
    }
}

/// `is_link`: whether the recipient can follow the URL from the email, rather than load it as an
/// image or a resource.
fn is_link(c: &Candidate) -> bool {
    c.anchor.is_some()
        || c.pdf_link
        || c.sources.contains(SOURCE_QR)
        || (c.sources.contains(SOURCE_BODY) && !c.in_parsed_body)
}

/// `str[:n]`, by characters.
fn chars_prefix(text: &str, n: usize) -> &str {
    match text.char_indices().nth(n) {
        Some((at, _)) => &text[..at],
        None => text,
    }
}

impl LureUrlAnalyzer {
    /// `_is_button`: the link or its parent has a button's role, class or style.
    fn is_button(&self, tree: &Tree, tag: usize) -> bool {
        for node in [Some(tag), tree.parent(tag)].into_iter().flatten() {
            if !matches!(tree.node(node), Node::Element { .. }) {
                continue;
            }
            if tree.get(node, "role").map(AttrValue::joined).as_deref() == Some("button") {
                return true;
            }
            let classes = match tree.get(node, "class") {
                Some(AttrValue::List(parts)) => parts.clone(),
                Some(AttrValue::Text(text)) if !text.is_empty() => vec![text.clone()],
                _ => Vec::new(),
            };
            if classes.iter().any(|c| {
                let lower = pystr::lower(c);
                lower.contains("btn") || lower.contains("button")
            }) {
                return true;
            }
            let style = tree.get(node, "style").map(AttrValue::joined);
            if self
                .button_style
                .is_match(style.as_deref().unwrap_or_default())
            {
                return true;
            }
            if tree
                .get(node, "bgcolor")
                .is_some_and(|v| !v.joined().is_empty())
            {
                return true;
            }
        }
        false
    }

    /// `parse_html_body`: the body's clickable links, keyed by their URL as written and as
    /// urlfinderlib spells it, the first link of a URL winning, each with whether it's in a signature
    /// block or a quoted message, and the text of the newest message. None where BeautifulSoup would
    /// raise.
    fn parse_html_body(&self, html: &str, settings: &LureSettings) -> Option<ParsedBody> {
        let tree = ace_lxml::soup::parse(html)?;
        let ends = subtree_ends(&tree);
        let mut body = ParsedBody::default();
        let mut regions = BodyRegions::new(settings);
        let mut position = 0;
        let mut link_depth: usize = 0;
        let mut line = Line::default();
        // each link with the flags of its line, which can change until the body is done
        let mut anchors: Vec<Anchor> = Vec::new();
        let mut keys: Vec<(String, usize)> = Vec::new();
        let mut anchor_flags: Vec<(usize, usize)> = Vec::new();

        for event in walk(&tree, &ends) {
            let (start, node) = match event {
                Event::Text(node) => {
                    let text = tree.text(node).unwrap_or_default();
                    if !pystr::strip(text).is_empty() {
                        line.parts.push(text.to_owned());
                        line.checked = line.checked || link_depth == 0;
                    }
                    continue;
                }
                Event::Start(node) => (true, node),
                Event::End(node) => (false, node),
            };
            let name = tree.name(node).unwrap_or_default();
            if LINE_BREAK_TAGS.contains(&name) {
                line.end(&mut regions, &mut anchor_flags);
            }
            if !LINK_TAGS.contains(&name) {
                if start && is_quote_container(&tree, node) {
                    line.end(&mut regions, &mut anchor_flags);
                    regions.quote();
                }
                continue;
            }
            if !start {
                link_depth = link_depth.saturating_sub(1);
                continue;
            }
            link_depth += 1;
            let href = tree
                .get(node, if name == "form" { "action" } else { "href" })
                .map(AttrValue::joined);
            let Some(href) = href.filter(|h| !pystr::strip(h).is_empty()) else {
                continue;
            };
            let mut text = descendant_text(&tree, &ends, node);
            if text.is_empty()
                && let Some(image) = (node + 1..ends[node]).find(|&i| tree.name(i) == Some("img"))
            {
                let alt = tree
                    .get(image, "alt")
                    .map(AttrValue::joined)
                    .filter(|a| !a.is_empty());
                text = match alt {
                    Some(alt) => format!("[image: {alt}]"),
                    None => "[image]".to_owned(),
                };
            }
            anchors.push(Anchor {
                text: chars_prefix(&text, ANCHOR_TEXT_MAX_LEN).to_owned(),
                button: self.is_button(&tree, node),
                position,
                signature: false,
                quoted: false,
                pdf: false,
            });
            position += 1;
            line.anchors.push(anchors.len() - 1);
            let href = pystr::strip(&href);
            for key in [href.to_owned(), normalize_url(href)] {
                keys.push((key, anchors.len() - 1));
            }
        }
        line.end(&mut regions, &mut anchor_flags);
        for (anchor, flags) in anchor_flags {
            let [signature, quoted] = regions.flags(flags);
            anchors[anchor].signature = signature;
            anchors[anchor].quoted = quoted;
        }
        for (key, anchor) in keys {
            body.anchors
                .entry(key)
                .or_insert_with(|| anchors[anchor].clone());
        }
        body.newest_text = regions.newest_text();
        Some(body)
    }
}

/// One step of ace3's `_walk`: a tag starting or ending, or a string that is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Start(usize),
    Text(usize),
    End(usize),
}

/// `_walk`: the tree's tags and its plain strings in document order, each tag with its end, and
/// nothing of what's inside a tag whose text is never shown. Comments, doctypes and the strings of
/// scripts and styles are other kinds of string, and never shown either.
fn walk(tree: &Tree, ends: &[usize]) -> Vec<Event> {
    let mut events = Vec::new();
    let mut open: Vec<usize> = Vec::new();
    let mut node = 1;
    while node < tree.len() {
        while let Some(&top) = open.last() {
            if node < ends[top] {
                break;
            }
            events.push(Event::End(top));
            open.pop();
        }
        match tree.node(node) {
            Node::Element { name, .. } => {
                events.push(Event::Start(node));
                if TEXT_SKIP_PARENTS.contains(&name.as_str()) {
                    events.push(Event::End(node));
                    node = ends[node];
                    continue;
                }
                open.push(node);
            }
            Node::Text {
                kind: StringKind::Plain,
                ..
            } => events.push(Event::Text(node)),
            _ => {}
        }
        node += 1;
    }
    while let Some(top) = open.pop() {
        events.push(Event::End(top));
    }
    events
}

/// `_is_quote_container`: a tag mail clients put an earlier message in.
fn is_quote_container(tree: &Tree, tag: usize) -> bool {
    let attr = |name: &str| tree.get(tag, name).map(AttrValue::joined);
    if tree.name(tag) == Some("blockquote")
        && attr("type").is_some_and(|t| pystr::lower(&t) == "cite")
    {
        return true;
    }
    // Outlook's reply header; a message sent on from Outlook on the web prefixes it with x_
    if attr("id").is_some_and(|id| id.ends_with("divRplyFwdMsg")) {
        return true;
    }
    match tree.get(tag, "class") {
        Some(AttrValue::List(classes)) => classes
            .iter()
            .any(|c| QUOTE_CLASS_PREFIXES.iter().any(|p| c.starts_with(p))),
        _ => false,
    }
}

/// The line `parse_html_body` is on: its strings, its links, and whether it has text that isn't a
/// link's.
#[derive(Debug, Default)]
struct Line {
    parts: Vec<String>,
    anchors: Vec<usize>,
    checked: bool,
}

impl Line {
    /// `end_line`: hands the line to the regions and gives its links its flags.
    fn end(&mut self, regions: &mut BodyRegions<'_>, anchor_flags: &mut Vec<(usize, usize)>) {
        if !self.parts.is_empty() || !self.anchors.is_empty() {
            let flags = regions.line(&self.parts.join(" "), self.checked);
            anchor_flags.extend(self.anchors.iter().map(|&anchor| (anchor, flags)));
        }
        *self = Line::default();
    }
}

/// `str.split()`: the words between runs of whitespace.
fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(pystr::is_space).filter(|word| !word.is_empty())
}

/// `is_sign_off`: whether a line closes a message: "Respectfully," or "Thanks, Sam", but neither
/// "Thanks for the bid" nor "Thanks, please review the attached invoice.", which goes on with the
/// message.
fn is_sign_off(line: &str, phrases: &[String]) -> bool {
    if line.chars().count() > SIGN_OFF_MAX_LEN {
        return false;
    }
    let lower = pystr::lower(line);
    for phrase in phrases {
        let phrase = pystr::lower(phrase);
        if phrase.is_empty() {
            continue;
        }
        let Some(rest) = lower.strip_prefix(phrase.as_ref()) else {
            continue;
        };
        // "Thanks - Sam" is a sign-off, "Best-in-class pricing" is not
        if rest.is_empty()
            || rest.starts_with([',', '.', '!', ':'])
            || rest.starts_with(" -")
            || rest.starts_with(" \u{2013}")
        {
            return is_name(pystr::lstrip_chars(rest, ",.!:-\u{2013} "));
        }
    }
    false
}

/// `_is_name`: whether the text after a sign-off phrase is a name ("Sam.", "J. Smith") rather than
/// a sentence of the message ("Your document is ready.").
fn is_name(text: &str) -> bool {
    let count = words(text).count();
    count <= SIGN_OFF_NAME_WORDS && !(count > 1 && text.ends_with(SENTENCE_ENDS))
}

/// `is_sentence`: whether a line reads as a sentence of the message rather than a line of a
/// signature (a name, a title, an address).
fn is_sentence(line: &str, settings: &LureSettings) -> bool {
    let count = words(line).count();
    count > settings.sentence_words
        || (count >= settings.sentence_end_words && line.ends_with(SENTENCE_ENDS))
}

/// Whether a message's sign-off has been seen: not decided until the first line after it with text
/// of its own, then on until the next message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signature {
    None,
    Pending,
    On,
}

/// ace3's `BodyRegions`: follows a body line by line, in reading order: whether it has reached an
/// earlier message the email quotes, and whether it is in a signature block.
///
/// A signature block starts after a sign-off line that isn't the first line of its message
/// ("Thank you!" heads many phish), unless the first line after it with text of its own is a
/// sentence, and runs to the start of the next message. Lines of link text only between the two (a
/// "View invoice" button) are decided with it.
struct BodyRegions<'s> {
    settings: &'s LureSettings,
    quoted: bool,
    signature: Signature,
    /// Each line's [in a signature block, in a quoted message], which a caller reads by the index
    /// `line` gave it once the body is done: a line after a pending sign-off is decided later.
    flags: Vec<[bool; 2]>,
    /// The link text lines after a pending sign-off, and where they start in `newest`.
    undecided: Vec<usize>,
    undecided_start: usize,
    message_lines: usize,
    line_number: usize,
    /// A `From:` line that may start a reply header: where it is in `newest`, its line number and
    /// the fields seen.
    header: Option<(usize, usize, BTreeSet<String>)>,
    newest: Vec<String>,
    newest_len: usize,
}

impl<'s> BodyRegions<'s> {
    fn new(settings: &'s LureSettings) -> Self {
        BodyRegions {
            settings,
            quoted: false,
            signature: Signature::None,
            flags: Vec::new(),
            undecided: Vec::new(),
            undecided_start: 0,
            message_lines: 0,
            line_number: 0,
            header: None,
            newest: Vec::new(),
            newest_len: 0,
        }
    }

    /// An earlier message starts here.
    fn quote(&mut self) {
        self.quoted = true;
        self.signature = Signature::None;
        self.undecided.clear();
        self.message_lines = 0;
        self.header = None;
    }

    fn flags(&self, index: usize) -> [bool; 2] {
        self.flags[index]
    }

    /// Flags that no later line changes.
    fn fixed(&mut self, flags: [bool; 2]) -> usize {
        self.flags.push(flags);
        self.flags.len() - 1
    }

    /// Takes the next line and returns where its flags are. A line that is only link text isn't
    /// checked: a link's own text never starts a message or a signature, nor decides one.
    fn line(&mut self, text: &str, checked: bool) -> usize {
        let line = words(text).collect::<Vec<_>>().join(" ");
        self.line_number += 1;
        if checked
            && !line.is_empty()
            && (QUOTE_MARKER.is_match(&line) || self.completes_header(&line))
        {
            self.quote();
            return self.fixed([false, true]);
        }

        let flags = self.fixed([false, self.quoted]);
        if self.signature == Signature::Pending {
            if !line.is_empty() && !checked {
                if self.undecided.is_empty() {
                    self.undecided_start = self.newest.len();
                }
                self.undecided.push(flags);
            } else {
                // a line with no text is a linked logo, which a signature often starts with
                self.signature = if is_sentence(&line, self.settings) {
                    Signature::None
                } else {
                    Signature::On
                };
                let on = self.signature == Signature::On;
                for &undecided in &self.undecided {
                    self.flags[undecided][0] = on;
                }
                if !self.undecided.is_empty() && on {
                    // they are the signature's, not the message's
                    self.truncate_newest(self.undecided_start);
                }
                self.undecided.clear();
            }
        }
        self.flags[flags][0] = self.signature == Signature::On;
        if checked
            && self.signature == Signature::None
            && self.message_lines > 0
            && is_sign_off(&line, &self.settings.sign_off_phrases)
        {
            self.signature = Signature::Pending;
        }

        if !line.is_empty() {
            self.message_lines += 1;
            if !self.quoted && !self.flags[flags][0] && self.newest_len < MAX_NEWEST_TEXT {
                self.newest_len += line.chars().count() + 1;
                self.newest.push(line);
            }
        }
        flags
    }

    /// `_completes_header`: whether a line completes a reply header: `From:`, then `Sent:` or
    /// `Date:`, and `To:` or `Subject:`. A lone `From:` line, as fake voicemail and file share
    /// notices have above their button, starts no message.
    fn completes_header(&mut self, line: &str) -> bool {
        let Some(found) = HEADER_FIELD.captures(line) else {
            return false;
        };
        let name = pystr::lower(found.get(1).map_or("", |m| m.as_str())).into_owned();
        if name == "from" {
            self.header = Some((self.newest.len(), self.line_number, BTreeSet::from([name])));
            return false;
        }
        let line_number = self.line_number;
        let Some((index, from_line, names)) = self.header.as_mut() else {
            return false;
        };
        if line_number - *from_line > MAX_HEADER_LINES {
            return false;
        }
        names.insert(name);
        let has = |wanted: [&str; 2]| wanted.iter().any(|n| names.contains(*n));
        if !(has(["sent", "date"]) && has(["to", "subject"])) {
            return false;
        }
        // the header is the earlier message's, not the newest one's
        let index = *index;
        self.truncate_newest(index);
        true
    }

    fn truncate_newest(&mut self, index: usize) {
        let index = index.min(self.newest.len());
        let removed: usize = self.newest[index..]
            .iter()
            .map(|line| line.chars().count() + 1)
            .sum();
        self.newest_len -= removed;
        self.newest.truncate(index);
    }

    fn newest_text(&self) -> String {
        self.newest.join("\n")
    }
}

/// `parse_text_body`: whether each URL in a plain text body is in a signature block or a quoted
/// message, and the text of the newest message.
fn parse_text_body(text: &str, settings: &LureSettings) -> ParsedBody {
    let mut body = ParsedBody::default();
    let mut regions = BodyRegions::new(settings);
    let mut url_flags: Vec<(String, usize)> = Vec::new();
    for line in pystr::splitlines(text) {
        if pystr::strip(line).is_empty() {
            continue;
        }
        let tokens: Vec<&str> = words(line)
            .map(|token| pystr::strip_chars(token, URL_TOKEN_PUNCTUATION))
            .collect();
        let urls: Vec<&str> = tokens
            .iter()
            .copied()
            .filter(|token| {
                let lower = pystr::lower(token);
                lower.starts_with("http://") || lower.starts_with("https://")
            })
            .collect();
        // a line quoted with ">" is an earlier message's, even between the lines of the reply; a
        // line of URLs only is a plain text body's link text
        let flags = if pystr::lstrip(line).starts_with('>') {
            regions.fixed([false, true])
        } else {
            regions.line(line, urls.len() < tokens.len())
        };
        for url in urls {
            for key in [url.to_owned(), normalize_url(url)] {
                url_flags.push((key, flags));
            }
        }
    }
    for (key, flags) in url_flags {
        let [signature, quoted] = regions.flags(flags);
        body.text_urls.entry(key).or_insert((signature, quoted));
    }
    body.newest_text = regions.newest_text();
    body
}

/// Whether `text` has a word boundary at byte `at`, as `re`'s `\b` for a str pattern.
fn word_boundary(text: &str, at: usize) -> bool {
    let before = text[..at].chars().next_back().is_some_and(pystr::is_word);
    let after = text[at..].chars().next().is_some_and(pystr::is_word);
    before != after
}

/// `find_phrase`: the first match of any of the phrases in the text as whole words, whatever their
/// case, as (start, end) in bytes. Of two phrases found at one place, the first listed.
fn find_phrase(phrases: &[String], text: &str) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;
    for phrase in phrases.iter().filter(|p| !p.is_empty()) {
        let Ok(pattern) = Regex::new(&format!("(?i){}", regex::escape(phrase))) else {
            continue;
        };
        let mut from = 0;
        while let Some(found) = pattern.find_at(text, from) {
            if word_boundary(text, found.start()) && word_boundary(text, found.end()) {
                if best.is_none_or(|(start, _)| found.start() < start) {
                    best = Some((found.start(), found.end()));
                }
                break;
            }
            // the next place the phrase could start
            from = found.start()
                + text[found.start()..]
                    .chars()
                    .next()
                    .map_or(1, char::len_utf8);
        }
    }
    best
}

/// `phrase_around`: the words around the match at bytes `start..end` of `text`, within its line,
/// `width` characters each way.
fn phrase_around(text: &str, start: usize, end: usize, width: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    // the match's place in characters, as Python counts
    let first = text[..start].chars().count();
    let last = first + text[start..end].chars().count();
    let line_start = chars[..first]
        .iter()
        .rposition(|c| *c == '\n')
        .map_or(0, |at| at + 1);
    let line_end = chars[last..]
        .iter()
        .position(|c| *c == '\n')
        .map_or(chars.len(), |at| last + at);
    let mut left = line_start.max(first.saturating_sub(width));
    let mut right = line_end.min(last + width);
    // whole words only
    if left > line_start
        && let Some(space) = chars[left..first].iter().position(|c| *c == ' ')
    {
        left += space + 1;
    }
    if right < line_end
        && let Some(space) = chars[last..right].iter().rposition(|c| *c == ' ')
    {
        right = last + space;
    }
    let around: String = chars[left..right].iter().collect();
    pystr::strip(&around).to_owned()
}

/// Where each node's descendants end: they follow it in document order, so node `i`'s are
/// `i + 1..ends[i]`.
fn subtree_ends(tree: &Tree) -> Vec<usize> {
    let mut ends: Vec<usize> = (1..=tree.len()).collect();
    for node in (1..tree.len()).rev() {
        if let Some(parent) = tree.parent(node) {
            ends[parent] = ends[parent].max(ends[node]);
        }
    }
    ends
}

/// `tag.get_text(" ", strip=True)`: the tag's plain strings, each stripped, the empty ones left out,
/// joined by spaces.
fn descendant_text(tree: &Tree, ends: &[usize], tag: usize) -> String {
    let mut parts = Vec::new();
    for node in tag + 1..ends[tag] {
        if let Node::Text {
            text,
            kind: StringKind::Plain,
        } = tree.node(node)
        {
            let stripped = pystr::strip(text);
            if !stripped.is_empty() {
                parts.push(stripped);
            }
        }
    }
    parts.join(" ")
}

/// `carried_urls`: the http(s) URLs in a URL's query string, such as a click tracker's `?u=`.
fn carried_urls(url: &str) -> Vec<String> {
    let Ok(parsed) = urlparse(url, "", true) else {
        return Vec::new();
    };
    let Ok(pairs) = parse_qsl(&parsed.query, false, false, "&") else {
        return Vec::new();
    };
    pairs
        .into_iter()
        .map(|(_, value)| pystr::strip(&value).to_owned())
        .filter(|value| {
            let lower = pystr::lower(value);
            lower.starts_with("http://") || lower.starts_with("https://")
        })
        .collect()
}

/// `fold_carried_urls`: the URLs a candidate carries in its query string fold into it. A carried URL
/// sits percent-encoded inside its carrier, so carrying can't make a cycle, and in a chain only the
/// outermost link is left.
fn fold_carried_urls(tree: &TreeView, mut candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut by_value: HashMap<String, usize> = HashMap::new();
    for (i, c) in candidates.iter().enumerate() {
        let value = &tree.observable(c.observable).value;
        by_value.entry(value.clone()).or_insert(i);
        by_value.entry(normalize_url(value)).or_insert(i);
    }
    let mut folded = HashSet::new();
    for carrier in 0..candidates.len() {
        let carrier_value = tree
            .observable(candidates[carrier].observable)
            .value
            .clone();
        for value in carried_urls(&carrier_value) {
            let carried = by_value
                .get(&value)
                .or_else(|| by_value.get(&normalize_url(&value)))
                .copied();
            let Some(carried) = carried else {
                continue;
            };
            let carried_value = &tree.observable(candidates[carried].observable).value;
            if carried == carrier || candidates[carrier].carries.contains(carried_value) {
                continue;
            }
            folded.insert(candidates[carried].observable);
            let carried_value = carried_value.clone();
            candidates[carrier].carries.push(carried_value);
        }
    }
    candidates.retain(|c| !folded.contains(&c.observable));
    candidates
}

/// One call of `_walk`: what it visits and what it carries down.
struct Visit {
    index: usize,
    path: Option<String>,
    source: &'static str,
    attachment: Option<String>,
    wrapped_by: Option<String>,
    pdf_link: bool,
}

/// ace3's `CandidateCollector`: walks one email's subtree for the URLs it carries, recording where
/// each came from. A crawl's URLs come after the click, so they're skipped, and so is an attached
/// email, which has a result of its own.
struct Collector<'t, F> {
    tree: &'t TreeView,
    index: &'t TreeIndex,
    module: &'t LureUrlAnalyzer,
    settings: &'t LureSettings,
    read_file: F,
    /// By observable, in the order first recorded.
    candidates: Vec<Candidate>,
    by_observable: HashMap<usize, usize>,
    wrappers: HashSet<usize>,
    /// ace3 keys a visit by the observable's uuid and the source; it has an observable for each
    /// path of a file, so a file's key here has the path it was reached under.
    visited: HashSet<(usize, Option<String>, &'static str)>,
    has_inner_email: bool,
    /// Each PDF link annotation's anchor, the name of its PDF and how many distinct links that PDF
    /// has, by its URL as written and as urlfinderlib spells it, the first PDF walked winning.
    pdf_links: HashMap<String, (Anchor, String, usize)>,
    /// The text of the newest message of the email, from its body parts.
    body_text: String,
}

impl<'t, F: FnMut(&str) -> Option<Vec<u8>>> Collector<'t, F> {
    fn new(
        tree: &'t TreeView,
        index: &'t TreeIndex,
        module: &'t LureUrlAnalyzer,
        settings: &'t LureSettings,
        read_file: F,
    ) -> Self {
        Collector {
            tree,
            index,
            module,
            settings,
            read_file,
            candidates: Vec::new(),
            by_observable: HashMap::new(),
            wrappers: HashSet::new(),
            visited: HashSet::new(),
            has_inner_email: false,
            pdf_links: HashMap::new(),
            body_text: String::new(),
        }
    }

    /// `CandidateCollector.collect`. `recorded` is the email result's record of its parts, which
    /// says which are its body (`EmailAnalysis.is_body_part`, ace3's 5474fd6b).
    fn collect(&mut self, email_result: usize, recorded: Option<&[EmailPart]>) -> Vec<Candidate> {
        let tree = self.tree;
        let mut anchors: HashMap<String, Anchor> = HashMap::new();
        let mut text_urls: HashMap<String, (bool, bool)> = HashMap::new();
        let mut newest_text: Vec<String> = Vec::new();
        let mut parsed_body = false;
        let parts: Vec<(usize, String)> = tree.results[email_result]
            .added
            .iter()
            .filter_map(|a| {
                let path = a.path.clone()?;
                let o = tree.observable(a.observable);
                let part = o.kind == ObservableKind::File
                    && !NON_PART_YARA_TYPES
                        .iter()
                        .any(|t| o.has_yara_type(&path, t));
                part.then_some((a.observable, path))
            })
            .collect();

        // the email module also adds an attached email's parts to this email, and those are the
        // inner email's lure, not this one's
        let mut inner_parts: HashSet<&str> = HashSet::new();
        for (part, _) in &parts {
            if let Some(inner) = self.index.result_of(tree, *part, EmailAnalysis::NAME) {
                self.has_inner_email = true;
                inner_parts.insert(&tree.observable(*part).value);
                for added in &tree.results[inner].added {
                    let o = tree.observable(added.observable);
                    if o.kind == ObservableKind::File {
                        inner_parts.insert(&o.value);
                    }
                }
            }
        }

        let paths: Vec<&str> = parts.iter().map(|(_, path)| path.as_str()).collect();
        let body_parts: HashMap<usize, bool> = EmailAnalysis::body_parts_in(recorded, &paths)
            .into_iter()
            .collect();
        for (at, (part, path)) in parts.iter().enumerate() {
            let observable = tree.observable(*part);
            if inner_parts.contains(observable.value.as_str()) {
                continue;
            }
            if let Some(&html) = body_parts.get(&at) {
                if let Some(content) = self.read_body(*part) {
                    let body = if html {
                        self.module.parse_html_body(&content, self.settings)
                    } else {
                        Some(parse_text_body(&content, self.settings))
                    };
                    match body {
                        Some(body) => {
                            // dict.update: a later body's link replaces an earlier one's
                            anchors.extend(body.anchors);
                            text_urls.extend(body.text_urls);
                            if !body.newest_text.is_empty() {
                                newest_text.push(body.newest_text);
                            }
                            parsed_body = parsed_body || html;
                        }
                        // the URLs are still scored, only without their anchors
                        None => tracing::warn!(
                            path = %path,
                            "unable to parse an email body for lure links"
                        ),
                    }
                }
                self.walk(*part, Some(path), SOURCE_BODY, None, None, false);
            } else {
                let name = path.rsplit('/').next().unwrap_or_default();
                self.walk(
                    *part,
                    Some(path),
                    SOURCE_ATTACHMENT,
                    Some(name.to_owned()),
                    None,
                    false,
                );
            }
        }

        self.body_text = newest_text.join("\n");

        let wrappers = &self.wrappers;
        let mut result: Vec<Candidate> = self
            .candidates
            .iter()
            .filter(|c| !wrappers.contains(&c.observable))
            .cloned()
            .collect();
        for c in result.iter_mut() {
            let value = tree.observable(c.observable).value.clone();
            let keys: Vec<String> = [c.wrapped_by.clone(), Some(value)]
                .into_iter()
                .flatten()
                .filter(|key| !key.is_empty())
                .collect();
            if c.sources.contains(SOURCE_BODY) {
                c.in_parsed_body = parsed_body;
                if parsed_body {
                    c.anchor = lookup(&anchors, &keys).cloned();
                }
                (c.signature, c.quoted) = match &c.anchor {
                    Some(anchor) => (anchor.signature, anchor.quoted),
                    None => lookup(&text_urls, &keys).copied().unwrap_or_default(),
                };
            }
            if c.anchor.is_none()
                && c.pdf_link
                && let Some((anchor, name, count)) = lookup(&self.pdf_links, &keys)
            {
                c.anchor = Some(anchor.clone());
                c.pdf_name = Some(name.clone());
                c.pdf_link_count = *count;
            }
        }
        fold_carried_urls(tree, result)
    }

    /// `_record_pdf_links`: the links of a PDF's `pdf_link_text` result, each with the text the PDF
    /// shows under it, or its line's, as its anchor.
    fn record_pdf_links(&mut self, pdf_name: &str, details: &serde_json::Value) {
        let Ok(analysis) = serde_json::from_value::<PdfLinkTextAnalysis>(details.clone()) else {
            tracing::warn!("a pdf_link_text result's details don't read");
            return;
        };
        let count = analysis
            .links
            .iter()
            .map(|link| link.url.as_str())
            .collect::<HashSet<_>>()
            .len();
        for (position, link) in analysis.links.iter().enumerate() {
            let text = [&link.text, &link.line]
                .into_iter()
                .flatten()
                .find(|text| !text.is_empty())
                .map_or("", String::as_str);
            let anchor = Anchor {
                text: chars_prefix(text, ANCHOR_TEXT_MAX_LEN).to_owned(),
                button: false,
                position,
                signature: false,
                quoted: false,
                pdf: true,
            };
            let url = pystr::strip(&link.url);
            for key in [url.to_owned(), normalize_url(url)] {
                self.pdf_links
                    .entry(key)
                    .or_insert_with(|| (anchor.clone(), pdf_name.to_owned(), count));
            }
        }
    }

    /// `_read_body`: the body as UTF-8, its bad bytes left out; None for one too large to parse.
    fn read_body(&mut self, part: usize) -> Option<String> {
        let observable = self.tree.observable(part);
        if observable.size.is_none_or(|size| size > MAX_BODY_BYTES) {
            tracing::info!(
                sha256 = %observable.value,
                "an email body is too large to parse for lure links"
            );
            return None;
        }
        let Some(bytes) = (self.read_file)(&observable.value) else {
            tracing::error!(
                sha256 = %observable.value,
                "unable to read an email body for lure links"
            );
            return None;
        };
        Some(pystr::decode_utf8_ignore(&bytes).into_owned())
    }

    /// `_walk`, with a stack of its own in place of recursion, so a deep tree can't exhaust the
    /// task's: each step is one of ace3's calls, in the order ace3 makes them.
    fn walk(
        &mut self,
        index: usize,
        path: Option<&String>,
        source: &'static str,
        attachment: Option<String>,
        wrapped_by: Option<String>,
        pdf_link: bool,
    ) {
        let tree = self.tree;
        let mut stack = vec![Visit {
            index,
            path: path.cloned(),
            source,
            attachment,
            wrapped_by,
            pdf_link,
        }];
        while let Some(visit) = stack.pop() {
            let observable = tree.observable(visit.index);
            // recorded on every visit: urlfinderlib also extracts the URL inside a wrapper directly,
            // so the visit through the wrapper may not be the first
            if observable.kind == ObservableKind::Url {
                self.record(
                    visit.index,
                    visit.source,
                    visit.attachment.as_deref(),
                    visit.wrapped_by.as_deref(),
                    visit.pdf_link,
                );
            }
            let key_path = (observable.kind == ObservableKind::File)
                .then(|| visit.path.clone().unwrap_or_default());
            if !self.visited.insert((visit.index, key_path, visit.source)) {
                continue;
            }
            let mut children = Vec::new();
            if observable.kind == ObservableKind::Url {
                for child in self
                    .index
                    .results_on(tree, visit.index)
                    .filter(|r| PROTECTED.contains(&r.analysis_type.as_str()))
                    .flat_map(|r| r.added.iter().map(|a| a.observable))
                    .filter(|&child| tree.observable(child).kind == ObservableKind::Url)
                {
                    self.wrappers.insert(visit.index);
                    children.push(Visit {
                        index: child,
                        path: None,
                        source: visit.source,
                        attachment: visit.attachment.clone(),
                        wrapped_by: visit
                            .wrapped_by
                            .clone()
                            .or_else(|| Some(observable.value.clone())),
                        pdf_link: visit.pdf_link,
                    });
                }
            } else if observable.kind == ObservableKind::File {
                let link_annotations = visit
                    .path
                    .as_ref()
                    .is_some_and(|p| observable.has_yara_type(p, PDF_LINK_ANNOTATIONS_YARA_TYPE));
                let results: Vec<&ace_sdk::tree::TreeResult> = self
                    .index
                    .results_on(tree, visit.index)
                    .filter(|r| r.module != PHISHKIT && r.analysis_type != EmailAnalysis::NAME)
                    .collect();
                // A PDF's own links are recorded before anything below it is walked, so a link the
                // PDF and Ghostscript's rewrite of it both have is named for the PDF. ace3 records
                // them where pdf_link_text's analysis falls among the PDF's, in the order its engine
                // ran the modules, which isn't the same from one set of modules to the next: before
                // pdf_analyzer's in the reference dumps, and after it in the trees, where the link is
                // named for the rewrite. ace-rs's results land in any order, so it takes one.
                let name = visit
                    .path
                    .as_deref()
                    .and_then(|p| p.rsplit('/').next())
                    .unwrap_or_default()
                    .to_owned();
                for details in results
                    .iter()
                    .filter(|r| r.module == PdfLinkTextAnalysis::MODULE)
                    .filter_map(|r| r.details.as_ref())
                {
                    self.record_pdf_links(&name, details);
                }
                for result in results {
                    let child_source = if result.module == QRCODE {
                        SOURCE_QR
                    } else {
                        visit.source
                    };
                    for added in &result.added {
                        children.push(Visit {
                            index: added.observable,
                            path: added.path.clone(),
                            source: child_source,
                            attachment: visit.attachment.clone(),
                            wrapped_by: None,
                            pdf_link: link_annotations,
                        });
                    }
                }
            }
            // the first child is walked first, as a recursive call would
            stack.extend(children.into_iter().rev());
        }
    }

    /// `_record`.
    fn record(
        &mut self,
        index: usize,
        source: &'static str,
        attachment: Option<&str>,
        wrapped_by: Option<&str>,
        pdf_link: bool,
    ) {
        let at = *self.by_observable.entry(index).or_insert_with(|| {
            self.candidates.push(Candidate::new(index));
            self.candidates.len() - 1
        });
        let c = &mut self.candidates[at];
        c.sources.insert(source);
        if let Some(attachment) = attachment.filter(|a| !a.is_empty())
            && !c.attachments.iter().any(|a| a == attachment)
        {
            c.attachments.push(attachment.to_owned());
        }
        if let Some(wrapped_by) = wrapped_by.filter(|w| !w.is_empty())
            && c.wrapped_by.is_none()
        {
            c.wrapped_by = Some(wrapped_by.to_owned());
        }
        c.pdf_link = c.pdf_link || pdf_link;
    }
}

/// `_lookup`: what a mapping holds for the first of the keys it has, as written or as urlfinderlib
/// spells it.
fn lookup<'m, V>(mapping: &'m HashMap<String, V>, keys: &[String]) -> Option<&'m V> {
    keys.iter().find_map(|key| {
        mapping
            .get(key)
            .or_else(|| mapping.get(&normalize_url(key)))
    })
}

/// `_matching_keyword`: the first keyword any of the values contains, case-blind.
fn matching_keyword<'k>(keywords: &'k [String], values: &[Option<&str>]) -> Option<&'k str> {
    for value in values.iter().flatten() {
        if value.is_empty() {
            continue;
        }
        let value = pystr::lower(value);
        for keyword in keywords {
            if value.contains(pystr::lower(keyword).as_ref()) {
                return Some(keyword);
            }
        }
    }
    None
}

/// `phishkit_chain.display_url`: the URL without its scheme, cut in the middle to `max_len`.
pub fn display_url(url: &str, max_len: usize) -> String {
    let value = if url.starts_with("http://") || url.starts_with("https://") {
        url.split_once("://").map_or(url, |(_, rest)| rest)
    } else {
        url
    };
    let chars: Vec<char> = value.chars().collect();
    if chars.len() > max_len {
        let tail = max_len / 3;
        let head: String = chars[..max_len - tail].iter().collect();
        let end: String = chars[chars.len() - tail..].iter().collect();
        return format!("{head}...{end}");
    }
    value.to_owned()
}

/// `saq.util.networking.is_subdomain`: `src` is `dst` or below it.
fn is_subdomain(src: &str, dst: &str) -> bool {
    let src = pystr::lower(src);
    let dst = pystr::lower(dst);
    let src: Vec<&str> = src.split('.').rev().collect();
    let dst: Vec<&str> = dst.split('.').rev().collect();
    dst.iter()
        .enumerate()
        .all(|(i, label)| src.get(i).is_some_and(|s| s == label))
}

/// `sender_domains`: the registrable domains of the email's From address and Return-Path.
fn sender_domains(email: &EmailAnalysis) -> BTreeSet<String> {
    let mut domains = BTreeSet::new();
    let Some(details) = &email.email else {
        return domains;
    };
    for value in [&details.from_address, &details.return_path]
        .into_iter()
        .flatten()
    {
        let Some(address) = ace_sdk::email_threads::normalize_email_address(value) else {
            continue;
        };
        let Some((_, domain)) = address.split_once('@') else {
            continue;
        };
        if !domain.is_empty() {
            domains.insert(ace_sdk::nrd::registrable_domain(domain));
        }
    }
    domains.remove("");
    domains
}

/// `score_candidates`: each candidate's score, with a reason for every signal that applied.
fn score_candidates(
    tree: &TreeView,
    candidates: &mut [Candidate],
    sender_domains: &BTreeSet<String>,
    settings: &LureSettings,
    body_text: &str,
) {
    let attachment_phrase = find_phrase(&settings.attachment_reference_keywords, body_text)
        .map(|(start, end)| phrase_around(body_text, start, end, 50))
        .filter(|phrase| !phrase.is_empty());
    let mut linked: BTreeSet<String> = candidates
        .iter()
        .filter(|c| is_link(c))
        .map(|c| ace_sdk::nrd::registrable_domain(&tree.observable(c.observable).value))
        .collect();
    linked.remove("");
    let external: BTreeSet<&String> = linked.difference(sender_domains).collect();
    let weights = &settings.weights;

    for c in candidates.iter_mut() {
        let observable = tree.observable(c.observable);
        let url = observable.value.as_str();
        let mut score = 0;
        let mut reasons = Vec::new();
        let mut highlights: Vec<Vec<String>> = Vec::new();
        let mut signal = |weight: i64, reason: String, values: Vec<String>| {
            score += weight;
            reasons.push(reason);
            highlights.push(values);
        };
        let parsed = urlparse(url, "", true).ok();
        let domain = ace_sdk::nrd::registrable_domain(url);
        let anchor_text = c.anchor.as_ref().map(|a| a.text.as_str());

        if c.sources.contains(SOURCE_QR) {
            signal(weights.qr, "decoded from a QR code".to_owned(), Vec::new());
        }
        if c.sources.contains(SOURCE_BODY) {
            signal(
                weights.body,
                "found in the email body".to_owned(),
                Vec::new(),
            );
        } else if c.sources.contains(SOURCE_ATTACHMENT) {
            signal(
                weights.attachment,
                format!("found in attachment {}", c.attachments.join(", ")),
                c.attachments.clone(),
            );
            if let Some(phrase) = &attachment_phrase {
                signal(
                    weights.attachment_reference,
                    format!("the email refers to its attachment: '{phrase}'"),
                    vec![phrase.clone()],
                );
            }
        }

        if let Some(anchor) = &c.anchor {
            let text = anchor_text.filter(|t| !t.is_empty());
            let place = if anchor.pdf { " in a PDF" } else { "" };
            signal(
                weights.clickable,
                match text {
                    Some(text) => format!("clickable link{place} with text '{text}'"),
                    None => format!("clickable link{place}"),
                },
                text.map(|t| vec![t.to_owned()]).unwrap_or_default(),
            );
            if anchor.button {
                signal(weights.button, "styled as a button".to_owned(), Vec::new());
            }
            if let Some(keyword) =
                matching_keyword(&settings.call_to_action_keywords, &[anchor_text])
            {
                signal(
                    weights.call_to_action,
                    format!("call-to-action text ({keyword})"),
                    Vec::new(),
                );
            }
        } else if c.pdf_link {
            signal(
                weights.clickable,
                "clickable link in a PDF".to_owned(),
                Vec::new(),
            );
        } else if c.in_parsed_body && !c.sources.contains(SOURCE_QR) {
            signal(
                weights.not_a_link,
                "not a clickable link in the body".to_owned(),
                Vec::new(),
            );
        }

        if let Some(name) = c.pdf_name.as_ref().filter(|name| !name.is_empty())
            && c.pdf_link_count == 1
        {
            signal(
                weights.only_link,
                format!("the only link in {name}"),
                vec![name.clone()],
            );
        }
        if c.signature {
            signal(
                weights.signature_block,
                "in a signature block".to_owned(),
                Vec::new(),
            );
        }
        if c.quoted {
            signal(
                weights.quoted_message,
                "in an earlier message the email quotes".to_owned(),
                Vec::new(),
            );
        }

        if let Some(wrapper) = &c.wrapped_by {
            signal(
                weights.unwrapped,
                format!(
                    "unwrapped from {}",
                    display_url(wrapper, DISPLAY_URL_MAX_LEN)
                ),
                Vec::new(),
            );
        }
        if !c.carries.is_empty() {
            let carried: Vec<String> = c.carries.iter().map(|u| display_url(u, 60)).collect();
            signal(
                0,
                format!(
                    "carries {} URL{}: {}",
                    carried.len(),
                    if carried.len() == 1 { "" } else { "s" },
                    carried.join(", ")
                ),
                carried,
            );
        }
        if observable.detections > 0 {
            signal(
                weights.detection,
                "has detection points".to_owned(),
                Vec::new(),
            );
        }
        if !domain.is_empty() && external.len() == 1 && external.contains(&domain) {
            signal(
                weights.only_domain,
                "the only linked external domain".to_owned(),
                Vec::new(),
            );
        }

        if let Some(parsed) = &parsed {
            let path = pystr::lower(&parsed.path);
            if STATIC_EXTENSIONS.iter().any(|e| path.ends_with(e)) {
                signal(
                    weights.static_,
                    "points at an image or static resource".to_owned(),
                    Vec::new(),
                );
            }
        }
        if let Some(keyword) = matching_keyword(&settings.noise_keywords, &[Some(url), anchor_text])
        {
            signal(
                weights.noise,
                format!("looks like a footer link ({keyword})"),
                Vec::new(),
            );
        }
        if !domain.is_empty() && sender_domains.contains(&domain) {
            signal(
                weights.sender_domain,
                format!("same domain as the sender ({domain})"),
                Vec::new(),
            );
        }
        if let Some(host) = parsed
            .as_ref()
            .and_then(|p| p.hostname())
            .filter(|h| !h.is_empty())
            && settings
                .benign_domains
                .iter()
                .any(|d| is_subdomain(&host, d))
        {
            signal(
                weights.benign,
                "benign infrastructure domain".to_owned(),
                Vec::new(),
            );
        }

        c.score = score;
        c.reasons = reasons;
        c.highlights = highlights;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_url_is_shown_without_its_scheme_and_cut_in_the_middle() {
        assert_eq!(display_url("https://example.com/a", 100), "example.com/a");
        assert_eq!(
            display_url("ftp://example.com/a", 100),
            "ftp://example.com/a"
        );
        let long = format!("https://example.com/{}", "a".repeat(200));
        let shown = display_url(&long, 60);
        assert_eq!(shown.chars().count(), 63);
        assert!(shown.starts_with("example.com/"));
        assert!(shown.contains("..."));
    }

    #[test]
    fn subdomains_match_their_parent_only() {
        assert!(is_subdomain("fonts.googleapis.com", "fonts.googleapis.com"));
        assert!(is_subdomain(
            "a.Fonts.GoogleAPIs.com",
            "fonts.googleapis.com"
        ));
        assert!(!is_subdomain("googleapis.com", "fonts.googleapis.com"));
        assert!(!is_subdomain(
            "evilfonts.googleapis.com",
            "fonts.googleapis.com"
        ));
    }

    #[test]
    fn a_click_tracker_carries_the_urls_in_its_query() {
        assert_eq!(
            carried_urls("https://t.example/c?u=https%3A%2F%2Flure.example%2Fx&id=1&v=HTTP://b"),
            ["https://lure.example/x", "HTTP://b"]
        );
        assert!(carried_urls("http://[x/").is_empty());
    }

    // ---- ace3's tests of the bodies' regions (tests/saq/modules/email/test_lure.py at 37a765bf) ----

    const LURE: &str = "https://evil.example.net/doc/view?id=1";
    const SIGNATURE_LINK: &str = "https://www.estimating.example.org";
    const EARLIER: &str = "https://projects.example.org/bid/42";
    const EARLIER_SIGNATURE: &str = "https://www.example.org";

    fn html_body(html: &str, settings: &LureSettings) -> ParsedBody {
        LureUrlAnalyzer::init(settings)
            .expect("builds")
            .parse_html_body(html, settings)
            .expect("parses")
    }

    /// (in a signature block, in a quoted message) of the link to `url`.
    fn place(body: &ParsedBody, url: &str) -> (bool, bool) {
        let anchor = &body.anchors[url];
        (anchor.signature, anchor.quoted)
    }

    #[test]
    fn a_thread_has_a_signature_block_in_each_message() {
        let html = format!(
            r#"<html><body>
<p>Hi all,</p>
<p>Please review the attached bid documents and confirm by Friday.</p>
<p>Respectfully,</p>
<p>Pat Doe<br>Estimator</p>
<p><a href="{SIGNATURE_LINK}">signature</a></p>
<div id="divRplyFwdMsg"><b>From:</b> Sam Roe &lt;sam@example.org&gt;<br><b>Sent:</b> Monday</div>
<p>Here is the <a href="{EARLIER}">project page</a>.</p>
<p>Regards,<br>Sam</p>
<p><a href="{EARLIER_SIGNATURE}">www.example.org</a></p>
</body></html>"#
        );
        let body = html_body(&html, &LureSettings::default());
        assert_eq!(place(&body, SIGNATURE_LINK), (true, false));
        // a new message ends the signature block above it
        assert_eq!(place(&body, EARLIER), (false, true));
        // and each message has its own
        assert_eq!(place(&body, EARLIER_SIGNATURE), (true, true));
        assert!(
            body.newest_text
                .contains("Please review the attached bid documents and confirm by Friday.")
        );
        assert!(!body.newest_text.contains("Here is the"));
    }

    #[test]
    fn each_quote_marker_starts_an_earlier_message() {
        for quote in [
            r#"<div class="gmail_quote"><div class="gmail_attr">On Mon, Sam wrote:</div><blockquote class="gmail_quote">"#,
            r#"<blockquote type="cite">"#,
            r#"<div id="x_divRplyFwdMsg">"#,
            "<p>On Mon, Oct 5, 2026 at 9:00 AM Sam Roe &lt;sam@example.org&gt; wrote:</p><div>",
            "<p>---------- Forwarded message ---------</p><div>",
        ] {
            let html = format!(
                r#"<p>See the attached file.</p><p>Thanks,</p><p><a href="{SIGNATURE_LINK}">signature</a></p><p>Pat</p>{quote}<p>see <a href="{EARLIER}">this</a></p></div>"#
            );
            let body = html_body(&html, &LureSettings::default());
            assert_eq!(place(&body, SIGNATURE_LINK), (true, false), "{quote}");
            assert_eq!(place(&body, EARLIER), (false, true), "{quote}");
        }
    }

    #[test]
    fn a_links_own_text_is_never_a_sign_off() {
        let html =
            format!(r#"<p><a href="{LURE}">Thanks!</a></p><p><a href="{EARLIER}">On it</a></p>"#);
        assert!(!html_body(&html, &LureSettings::default()).anchors[EARLIER].signature);
    }

    #[test]
    fn thanks_is_not_always_a_sign_off() {
        for html in [
            // an inline tag does not make its text a line of its own
            format!(
                r#"<p>Hello,</p><p><b>Thank you</b> for your payment. <a href="{LURE}">View invoice</a></p>"#
            ),
            format!(
                r#"<p>Hello,</p><p><span>Best</span> offers this week: <a href="{LURE}">Shop</a></p>"#
            ),
            // a heading that thanks the recipient before anything else is not a sign-off
            format!(r#"<h2>Thank you!</h2><p><a href="{LURE}">View invoice</a></p>"#),
            // nor is one that prose follows
            format!(
                r#"<p>Hello,</p><h2>Thank you!</h2><p>Your payment of $500 was received today and your receipt is ready to view. <a href="{LURE}">View invoice</a></p>"#
            ),
            // nor is a sign-off inside a table cell's text
            format!(
                r#"<table><tr><td>Hello, <b>Thanks</b>, your order shipped</td><td><a href="{LURE}">Track</a></td></tr></table>"#
            ),
            // a button's text does not decide a sign-off, and nothing after it does either
            format!(
                r#"<p>Dear customer,</p><h2>Thank you!</h2><p><a href="{LURE}">View invoice</a></p>"#
            ),
            format!(
                r#"<p><a href="https://www.example.com/web">View in browser</a></p><h2>Thank you!</h2><p><a href="{LURE}">View invoice</a></p>"#
            ),
            // the sentence below the button does
            format!(
                r#"<p>Dear customer,</p><h2>Thank you!</h2><p><a href="{LURE}">View invoice</a></p><p>Your payment of $500 was received today and your receipt is ready to view.</p>"#
            ),
        ] {
            assert!(
                !html_body(&html, &LureSettings::default()).anchors[LURE].signature,
                "{html}"
            );
        }
    }

    #[test]
    fn a_linked_logo_and_a_name_line_decide_a_sign_off() {
        // a signature's first line can be a linked logo with no text
        let html = format!(
            r#"<p>See the attached file.</p><p>Regards,</p><p><a href="{EARLIER_SIGNATURE}"><img src="logo.png"></a></p><p><a href="{SIGNATURE_LINK}">www.estimating.example.org</a></p>"#
        );
        let body = html_body(&html, &LureSettings::default());
        assert!(body.anchors[EARLIER_SIGNATURE].signature);
        assert!(body.anchors[SIGNATURE_LINK].signature);
        // the name line below decides the sign-off, and the link line between is the signature's
        let html = format!(
            r#"<p>See the attached file.</p><p>Thanks,</p><p><a href="{SIGNATURE_LINK}">www.estimating.example.org</a></p><p>Pat Doe</p>"#
        );
        assert!(html_body(&html, &LureSettings::default()).anchors[SIGNATURE_LINK].signature);
    }

    #[test]
    fn a_signatures_link_text_is_not_the_message() {
        // the link's text is the signature's once the name line decides it, so it refers to no
        // attachment
        let settings = LureSettings::default();
        let body = html_body(
            r#"<p>Please review the bid.</p><p>Thanks,</p><p><a href="https://www.example.org/terms">See the attached terms</a></p><p>Pat Doe</p>"#,
            &settings,
        );
        assert_eq!(body.newest_text, "Please review the bid.\nThanks,");
        assert_eq!(
            find_phrase(&settings.attachment_reference_keywords, &body.newest_text),
            None
        );
    }

    #[test]
    fn a_quoted_message_does_not_decide_a_sign_off() {
        // the earlier message's own signature is no answer to the newest message's "Thank you!"
        let html = format!(
            r#"<p>Dear customer,</p><h2>Thank you!</h2><p><a href="{LURE}">View invoice</a></p><div id="divRplyFwdMsg"><p>From: Sam</p></div><p>Can you send it?</p><p>Regards,</p><p>Sam Roe</p>"#
        );
        assert_eq!(
            place(&html_body(&html, &LureSettings::default()), LURE),
            (false, false)
        );
    }

    #[test]
    fn the_head_a_script_and_a_comment_are_not_lines() {
        // the title would be the first line, and the heading a sign-off after it
        let html = format!(
            r#"<html><head><title>Invoice</title><style>p {{ color: red; }}</style></head><body><script>var x = 1;</script><h2>Thank you!</h2><p><a href="{LURE}">View invoice</a></p></body></html>"#
        );
        let body = html_body(&html, &LureSettings::default());
        assert!(!body.anchors[LURE].signature);
        assert_eq!(body.newest_text, "Thank you!\nView invoice");
        // Outlook's conditional comments, with a reply header inside, are never shown
        let html = format!(
            r#"<!--[if mso]><p>From: x</p><p>Sent: y</p><p>To: z</p><![endif]--><p>See the attached file.</p><p><a href="{LURE}">View</a></p>"#
        );
        let body = html_body(&html, &LureSettings::default());
        assert_eq!(place(&body, LURE), (false, false));
        assert_eq!(body.newest_text, "See the attached file.\nView");
    }

    #[test]
    fn what_a_sentence_is_comes_from_the_settings() {
        let html = format!(
            r#"<p>Hello,</p><h2>Thank you!</h2><p>Your receipt is ready.</p><p><a href="{LURE}">View invoice</a></p>"#
        );
        // four words are not a sentence by default, so the heading is a sign-off
        assert!(html_body(&html, &LureSettings::default()).anchors[LURE].signature);
        let settings = LureSettings {
            sentence_end_words: 4,
            ..LureSettings::default()
        };
        assert!(!html_body(&html, &settings).anchors[LURE].signature);
        let settings = LureSettings {
            sentence_words: 3,
            ..LureSettings::default()
        };
        assert!(!html_body(&html, &settings).anchors[LURE].signature);
    }

    #[test]
    fn the_newest_text_stops_at_the_signature_and_keeps_a_sentence_after_thanks() {
        let settings = LureSettings::default();
        let body = html_body(
            "<p>Your account needs attention. <a href='https://evil.example.net/'>Verify</a></p><p>Regards,<br>Pat</p>\
             <p>This e-mail and any files attached to it are confidential and intended only for its addressee.</p>",
            &settings,
        );
        assert!(!body.newest_text.contains("confidential"));
        assert_eq!(
            find_phrase(&settings.attachment_reference_keywords, &body.newest_text),
            None
        );
        let html = format!(
            "<p>Hi John,</p><p>Thanks, please review the attached invoice.</p><p><a href='{LURE}'>View Invoice</a></p>\
             <p>Regards,</p><p>Accounts Team</p>"
        );
        let body = html_body(&html, &settings);
        assert!(!body.anchors[LURE].signature);
        assert!(body.newest_text.contains("View Invoice"));
    }

    #[test]
    fn a_from_line_alone_starts_no_message() {
        for html in [
            format!(
                r#"<p>From: IT Service Desk</p><p>You have a new voicemail. <a href="{LURE}">Listen</a></p>"#
            ),
            format!(
                r#"<table><tr><td>From:</td><td>IT Service Desk</td></tr><tr><td>Date:</td><td>Monday</td></tr></table><p>You have a new voicemail. <a href="{LURE}">Listen</a></p>"#
            ),
        ] {
            let body = html_body(&html, &LureSettings::default());
            assert!(!body.anchors[LURE].quoted, "{html}");
            assert!(body.newest_text.contains("You have a new voicemail."));
        }
    }

    #[test]
    fn a_deeply_nested_body_is_walked() {
        let html = format!(
            r#"{}<a href="{LURE}">View</a>{}"#,
            "<div>".repeat(5000),
            "</div>".repeat(5000)
        );
        assert_eq!(
            html_body(&html, &LureSettings::default()).anchors[LURE].text,
            "View"
        );
    }

    #[test]
    fn a_plain_text_body_has_its_regions_too() {
        let settings = LureSettings::default();
        let body = parse_text_body(
            &format!("Thank you!\nView your invoice: {LURE}\n"),
            &settings,
        );
        assert_eq!(body.text_urls[LURE], (false, false));
        // a line of URLs only does not decide a sign-off; a name line after it does
        let body = parse_text_body(&format!("Dear customer,\nThank you!\n{LURE}\n"), &settings);
        assert_eq!(body.text_urls[LURE], (false, false));
        let body = parse_text_body(
            &format!("See the attached file.\nThanks,\n{SIGNATURE_LINK}\nPat Doe\n"),
            &settings,
        );
        assert_eq!(body.text_urls[SIGNATURE_LINK], (true, false));
        // a reply header starts an earlier message, and is that message's
        let body = parse_text_body(
            &format!(
                "Please see the attached bid.\n\nFrom: Sam Roe\nSent: Monday\nTo: Pat Doe\nSubject: bid\nHere is {EARLIER}\n"
            ),
            &settings,
        );
        assert_eq!(body.text_urls[EARLIER], (false, true));
        assert_eq!(body.newest_text, "Please see the attached bid.");
    }

    #[test]
    fn a_plain_text_thread_is_read_line_by_line() {
        let text = format!(
            "Please review the attached bid documents.\n> {LURE}\n\nRespectfully,\nPat Doe\n<{SIGNATURE_LINK}>\n\n\
             -----Original Message-----\nFrom: Sam Roe\nHere is {EARLIER}.\n"
        );
        let body = parse_text_body(&text, &LureSettings::default());
        // a line quoted with ">" is an earlier message's, even inside the newest one
        assert_eq!(body.text_urls[LURE], (false, true));
        assert_eq!(body.text_urls[SIGNATURE_LINK], (true, false));
        assert_eq!(body.text_urls[EARLIER], (false, true));
        assert!(
            body.newest_text
                .starts_with("Please review the attached bid documents.")
        );
        assert!(!body.newest_text.contains(LURE));
        assert!(!body.newest_text.contains("Here is"));
    }

    #[test]
    fn many_reply_headers_after_a_full_message_cost_no_more_than_their_lines() {
        // ace3's fix (40ee8208): each header or signature re-counted the whole newest message
        for repeated in [
            "From: a\nSent: b\nTo: c\n",
            "-----Original Message-----\nHello\nThanks,\nhttps://a.example.com/\nPat\n",
        ] {
            let text = format!(
                "{}{}{EARLIER}\n",
                "x\n".repeat(10_000),
                repeated.repeat(20_000)
            );
            let body = parse_text_body(&text, &LureSettings::default());
            assert!(body.text_urls[EARLIER].1, "quoted");
        }
    }

    #[test]
    fn a_sign_off_is_a_phrase_then_nothing_or_a_name() {
        let phrases = LureSettings::default().sign_off_phrases;
        for (line, expected) in [
            ("Respectfully,", true),
            ("Thanks, Sam", true),
            ("Best", true),
            ("Kind regards.", true),
            ("Thanks - Sam", true),
            ("Thanks \u{2013} Sam", true),
            ("Thanks for the bid", false),
            ("Best-in-class pricing", false),
            ("Regards, Pat Doe", true),
            ("Thanks, Sam.", true),
            ("Best, J. Smith", true),
            // a sentence after the phrase is the message's, not a name
            ("Thanks, please review the attached invoice.", false),
            ("Thank you! Your document is ready.", false),
            // more words than a name has, with no final punctuation
            ("Thanks, please review the invoice below", false),
        ] {
            assert_eq!(is_sign_off(line, &phrases), expected, "{line}");
        }
        assert!(!is_sign_off(
            &format!("Regards,{}", " x".repeat(50)),
            &phrases
        ));
    }

    #[test]
    fn a_phrase_is_found_as_whole_words_and_shown_with_the_words_around_it() {
        let phrases = LureSettings::default().attachment_reference_keywords;
        let found = |text: &str| {
            find_phrase(&phrases, text).map(|(start, end)| text[start..end].to_owned())
        };
        // the first one in the text, so the longer phrase wins where it is there
        assert_eq!(
            found("Please find attached the bid.").as_deref(),
            Some("Please find attached")
        );
        assert_eq!(found("The bid is attached.").as_deref(), Some("attached"));
        assert_eq!(
            found("Please SEE ATTACHMENT for details").as_deref(),
            Some("SEE ATTACHMENT")
        );
        assert_eq!(
            find_phrase(&phrases, "enclosed is the form, see attachment").map(|m| m.0),
            Some(0)
        );
        // a banner or disclaimer on most mail
        assert_eq!(
            found("CAUTION: Do not click links or open attachments unless you know the sender."),
            None
        );
        assert_eq!(
            found("This e-mail and any attachments are confidential."),
            None
        );
        assert_eq!(found("unattached"), None);
        assert_eq!(find_phrase(&[String::new()], "anything"), None);

        let text = "Hi\nPlease review the attached bid documents.\nThanks";
        let (start, end) = find_phrase(&strings(&["attached"]), text).expect("found");
        assert_eq!(
            phrase_around(text, start, end, 50),
            "Please review the attached bid documents."
        );
        // whole words only, within the width
        let text = format!(
            "{} one two three attached four five six {}",
            "x".repeat(10),
            "y".repeat(10)
        );
        let (start, end) = find_phrase(&strings(&["attached"]), &text).expect("found");
        assert_eq!(
            phrase_around(&text, start, end, 15),
            "one two three attached four five six"
        );
        // counted in characters, not bytes
        let text = "é".repeat(60) + " see the attached file";
        let (start, end) = find_phrase(&strings(&["attached"]), &text).expect("found");
        assert_eq!(
            phrase_around(&text, start, end, 12),
            "see the attached file"
        );
    }

    #[test]
    fn a_pdfs_own_links_are_recorded_before_its_rewrites_whatever_order_the_results_landed_in() {
        // the link is named for the PDF, not for Ghostscript's rewrite of it, though here
        // pdf_analyzer's result, which added the rewrite, landed before the PDF's pdf_link_text
        let link = "https://docs.lure-example.net/bid";
        let links =
            |text: &str| json!({"links": [{"url": link, "page": 1, "text": text, "line": null}]});
        let file = |sha: &str, path: &str, meta: &[&str]| json!({"type": "file", "value": sha, "paths": [{"path": path, "yara_meta": meta}], "size": 10});
        let tree: TreeView = serde_json::from_value(json!({
            "this": 0,
            "observables": [
                file("e", "email.rfc822", &[]),
                file("p", "bid.pdf", &[]),
                file("g", "bid.pdf.gs.pdf", &[]),
                file("u", "bid.pdf.annotation_uris.txt", &["type=document.pdf.annotation_uris"]),
                {"type": "url", "value": link},
            ],
            "results": [
                {"observable": 0, "module": "email_analyzer", "analysis_type": "email_analysis",
                 "added": [{"observable": 1, "path": "bid.pdf"}]},
                {"observable": 1, "module": "pdf_analyzer", "analysis_type": "pdf_analysis",
                 "added": [{"observable": 2, "path": "bid.pdf.gs.pdf"},
                           {"observable": 3, "path": "bid.pdf.annotation_uris.txt"}]},
                {"observable": 2, "module": "pdf_link_text", "analysis_type": "pdf_link_text_analysis",
                 "details": links("Review bid rewritten")},
                {"observable": 1, "module": "pdf_link_text", "analysis_type": "pdf_link_text_analysis",
                 "details": links("Review bid")},
                {"observable": 3, "module": "url_extraction", "analysis_type": "url_extraction_analysis",
                 "added": [{"observable": 4}]},
            ],
        }))
        .expect("a tree");
        let settings = LureSettings::default();
        let module = LureUrlAnalyzer::init(&settings).expect("builds");
        let index = TreeIndex::new(&tree);
        let mut collector = Collector::new(&tree, &index, &module, &settings, |_| None);
        let candidates = collector.collect(0, None);
        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert_eq!(candidate.pdf_name.as_deref(), Some("bid.pdf"));
        assert_eq!(candidate.pdf_link_count, 1);
        assert_eq!(
            candidate.anchor.as_ref().map(|a| (a.text.as_str(), a.pdf)),
            Some(("Review bid", true))
        );
        assert_eq!(candidate.attachments, ["bid.pdf"]);
    }

    #[test]
    fn anchors_have_their_text_an_image_or_nothing() {
        let settings = LureSettings::default();
        let module = LureUrlAnalyzer::init(&settings).expect("builds");
        let anchors = module
            .parse_html_body(
                r#"<p><a href=" https://a.example/x ">Open <b>the</b> document</a>
                <a href="https://b.example/"><img alt="logo"></a>
                <a href="https://c.example/" class="Big-BTN">  </a>
                <form action="https://d.example/post"><td bgcolor="red"></td></form>
                <a href="">nothing</a><script>var a = "<a href='https://e.example/'>x</a>";</script></p>"#,
                &settings,
            )
            .expect("parses")
            .anchors;
        let a = &anchors["https://a.example/x"];
        assert_eq!(
            (a.text.as_str(), a.button, a.position),
            ("Open the document", false, 0)
        );
        assert_eq!(anchors["https://b.example"].text, "[image: logo]");
        assert_eq!(anchors["https://b.example/"].position, 1);
        assert!(anchors["https://c.example/"].button);
        assert_eq!(anchors["https://c.example/"].text, "");
        assert_eq!(anchors["https://d.example/post"].position, 3);
        assert!(!anchors.contains_key(""));
        assert!(!anchors.contains_key("https://e.example/"));
    }
}
