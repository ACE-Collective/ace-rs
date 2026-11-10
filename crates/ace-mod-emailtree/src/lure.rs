//! `lure_url_analyzer`, a port of ace3's `LureURLAnalyzer` (`saq/modules/email/lure.py`): which of an
//! email's URLs it lures its recipient to.
//!
//! ace3 waits for its final analysis, walks the email's subtree for the URLs it carries, recording
//! where each came from (a body part, an attachment, a QR code, a protected URL's wrapper, a PDF's
//! link annotations), reads the anchors of its HTML bodies with BeautifulSoup, scores each URL on
//! those signals and its settings' keywords and domains, and adds `crawl` to the best. Here the
//! module runs last (`Module::RUNS_LAST`) and walks the tree the core sends (`Module::READS_TREE`),
//! with the email's HTML bodies (`Module::READS_TREE_FILES`).
//!
//! ace3 reads its settings from `etc/lure_url.yaml`, which analysts edit and it reloads. Here they're
//! the module's settings, in the site's overlay, with the same keys and ace3's built-in values as
//! their defaults.

use std::collections::{BTreeSet, HashMap, HashSet};

use ace_lxml::soup::{AttrValue, Node, StringKind, Tree};
use ace_pycompat::parse::{parse_qsl, urlparse};
use ace_pycompat::pystr;
use ace_results::types::email::EmailAnalysis;
use ace_results::types::emailtree::{LureCandidate, LureUrlAnalysis};
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

/// The email's body parts are the unnamed text parts the email module extracts.
const BODY_PART_MARKERS: [&str; 2] = [".unknown_text_html", ".unknown_text_plain"];
const HTML_BODY_MARKER: &str = ".unknown_text_html";
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

/// ace3's `LureURLWeights`: what each signal adds to or takes from a candidate's score.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct LureWeights {
    pub qr: i64,
    pub body: i64,
    pub attachment: i64,
    pub clickable: i64,
    pub button: i64,
    pub call_to_action: i64,
    pub only_domain: i64,
    pub unwrapped: i64,
    pub detection: i64,
    pub not_a_link: i64,
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
            clickable: 25,
            button: 15,
            call_to_action: 20,
            only_domain: 10,
            unwrapped: 5,
            detection: 30,
            not_a_link: -15,
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
    /// How many ranked candidates to keep, the primary included. At least 1.
    pub max_candidates: usize,
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
            max_candidates: 5,
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
    });
    const READS_TREE_FILES: Option<TreeFiles> = Some(TreeFiles {
        names_containing: &[HTML_BODY_MARKER],
        max_size: MAX_BODY_BYTES,
    });
    type Output = LureUrlAnalysis;
    type Settings = LureSettings;

    fn init(settings: &LureSettings) -> Result<Self, ModuleError> {
        if settings.max_candidates < 1 {
            return Err(ModuleError::other("max_candidates must be at least 1"));
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
        let Some(email) = ctx.dependency_result::<EmailAnalysis>()? else {
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
        let mut collector = Collector::new(tree, &index, self, |sha256| {
            ctx.tree_file(sha256)
                .and_then(|path| std::fs::read(path).ok())
        });
        let candidates: Vec<Candidate> = collector
            .collect(email_result)
            .into_iter()
            .filter(|c| is_http_url(&tree.observable(c.observable).value))
            .collect();
        if candidates.is_empty() {
            return Ok(Outcome::Skipped("no lure url candidates".to_owned()));
        }
        let settings = ctx.settings();
        let mut candidates = candidates;
        score_candidates(tree, &mut candidates, &sender_domains(&email), settings);
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

/// Where a link sits in a body: its text, whether it's styled as a button, and its place, the
/// tie-break between equal scores.
#[derive(Debug, Clone, PartialEq)]
struct Anchor {
    text: String,
    button: bool,
    position: usize,
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
            score: 0,
            reasons: Vec::new(),
            highlights: Vec::new(),
        }
    }

    /// `Candidate.to_dict`, without ace3's `observable_uuid`: ace4's observables have no uuid, and
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

/// `Candidate.rank_key`: the highest score first, then the earliest in the body, then by value.
fn rank_key<'t>(tree: &'t TreeView, c: &Candidate) -> (i64, usize, &'t str) {
    (
        -c.score,
        c.anchor.as_ref().map_or(usize::MAX, |a| a.position),
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

    /// `parse_body_anchors`: the body's links, keyed by their URL as written and as urlfinderlib
    /// spells it, the first link of a URL winning. None where BeautifulSoup would raise.
    fn parse_body_anchors(&self, html: &str) -> Option<HashMap<String, Anchor>> {
        let tree = ace_lxml::soup::parse(html)?;
        let ends = subtree_ends(&tree);
        let mut anchors = HashMap::new();
        let mut position = 0;
        for tag in tree.elements() {
            let name = tree.name(tag).unwrap_or_default();
            if !matches!(name, "a" | "area" | "form") {
                continue;
            }
            let href = tree
                .get(tag, if name == "form" { "action" } else { "href" })
                .map(AttrValue::joined);
            let Some(href) = href.filter(|h| !pystr::strip(h).is_empty()) else {
                continue;
            };
            let mut text = descendant_text(&tree, &ends, tag);
            if text.is_empty()
                && let Some(image) = (tag + 1..ends[tag]).find(|&i| tree.name(i) == Some("img"))
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
            let anchor = Anchor {
                text: chars_prefix(&text, ANCHOR_TEXT_MAX_LEN).to_owned(),
                button: self.is_button(&tree, tag),
                position,
            };
            position += 1;
            let href = pystr::strip(&href);
            for key in [href.to_owned(), normalize_url(href)] {
                anchors.entry(key).or_insert_with(|| anchor.clone());
            }
        }
        Some(anchors)
    }
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
    read_file: F,
    /// By observable, in the order first recorded.
    candidates: Vec<Candidate>,
    by_observable: HashMap<usize, usize>,
    wrappers: HashSet<usize>,
    /// ace3 keys a visit by the observable's uuid and the source; it has an observable for each
    /// path of a file, so a file's key here has the path it was reached under.
    visited: HashSet<(usize, Option<String>, &'static str)>,
    has_inner_email: bool,
}

impl<'t, F: FnMut(&str) -> Option<Vec<u8>>> Collector<'t, F> {
    fn new(
        tree: &'t TreeView,
        index: &'t TreeIndex,
        module: &'t LureUrlAnalyzer,
        read_file: F,
    ) -> Self {
        Collector {
            tree,
            index,
            module,
            read_file,
            candidates: Vec::new(),
            by_observable: HashMap::new(),
            wrappers: HashSet::new(),
            visited: HashSet::new(),
            has_inner_email: false,
        }
    }

    /// `CandidateCollector.collect`.
    fn collect(&mut self, email_result: usize) -> Vec<Candidate> {
        let tree = self.tree;
        let mut anchors: HashMap<String, Anchor> = HashMap::new();
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

        for (part, path) in &parts {
            let observable = tree.observable(*part);
            if inner_parts.contains(observable.value.as_str()) {
                continue;
            }
            let name = path.rsplit('/').next().unwrap_or_default();
            if BODY_PART_MARKERS.iter().any(|m| name.contains(m)) {
                if name.contains(HTML_BODY_MARKER)
                    && let Some(html) = self.read_body(*part)
                {
                    match self.module.parse_body_anchors(&html) {
                        Some(found) => {
                            for (key, anchor) in found {
                                // dict.update: a later body's link replaces an earlier one's
                                anchors.insert(key, anchor);
                            }
                            parsed_body = true;
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

        let wrappers = &self.wrappers;
        let mut result: Vec<Candidate> = self
            .candidates
            .iter()
            .filter(|c| !wrappers.contains(&c.observable))
            .cloned()
            .collect();
        if parsed_body {
            for c in result.iter_mut() {
                if !c.sources.contains(SOURCE_BODY) {
                    continue;
                }
                c.in_parsed_body = true;
                let value = tree.observable(c.observable).value.clone();
                for value in [c.wrapped_by.clone(), Some(value)].into_iter().flatten() {
                    let anchor = anchors
                        .get(&value)
                        .or_else(|| anchors.get(&normalize_url(&value)));
                    if let Some(anchor) = anchor {
                        c.anchor = Some(anchor.clone());
                        break;
                    }
                }
            }
        }
        fold_carried_urls(tree, result)
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
                for result in self
                    .index
                    .results_on(tree, visit.index)
                    .filter(|r| r.module != PHISHKIT && r.analysis_type != EmailAnalysis::NAME)
                {
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
        let Some(address) = ace_mod_email::py::normalize_email_address(value) else {
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
) {
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
        }

        if let Some(anchor) = &c.anchor {
            let text = anchor_text.filter(|t| !t.is_empty());
            signal(
                weights.clickable,
                match text {
                    Some(text) => format!("clickable link with text '{text}'"),
                    None => "clickable link".to_owned(),
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

    #[test]
    fn anchors_have_their_text_an_image_or_nothing() {
        let module = LureUrlAnalyzer::init(&LureSettings::default()).expect("builds");
        let anchors = module
            .parse_body_anchors(
                r#"<p><a href=" https://a.example/x ">Open <b>the</b> document</a>
                <a href="https://b.example/"><img alt="logo"></a>
                <a href="https://c.example/" class="Big-BTN">  </a>
                <form action="https://d.example/post"><td bgcolor="red"></td></form>
                <a href="">nothing</a><script>var a = "<a href='https://e.example/'>x</a>";</script></p>"#,
            )
            .expect("parses");
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
