//! The help area (PLAN.md 5.11's `help` area, built with 7.10 batch 9): ace3's `app/help/`, the
//! training guides, written in Markdown and drawn by the GUI.
//!
//! Guides are grouped in sets, one per subsystem. A set is a directory under this crate's `help/`
//! named by its slug, holding one Markdown file per guide and the images those guides use under
//! `images/`, so a guide also reads correctly where the repository is browsed. The one set is SVS's:
//! ace3's `app/help/content/svs/` guides (ace3's own documentation, Apache-2.0 as this repository is),
//! rewritten to say what ace-rs does. Its five diagrams are brought, redrawn where ace-rs differs. Its
//! screenshots are of ace3's pages and aren't: the guides' screenshots are of ace-rs's own pages showing
//! made-up data, where ace-rs has the page ace3's guide illustrated, and `tools/help-screenshots/run`
//! draws them again when a page changes (its docstring says how). ace3's pictures with no page here:
//! `run-candidates` (a candidate's decisions are in the Result table, which `run-result-candidates`
//! shows), `run-expected-modal` and `run-close-modal` (ace-rs has no dialogs: the reason is a field
//! beside the buttons) and `run-logs` (a run's page links to the site's log search, and has no Logs
//! section).
//!
//! ace3's views, each `GET` only and for any signed-in user, since a guide describes screens that have
//! their own permissions and reading about one grants nothing on it:
//! - `help.help_index` (`help/index.html`): `GET /help`, every set with its guides.
//! - `help.guide_set`: `GET /help/{set}/` (and without the slash), which goes to the set's first guide.
//! - `help.guide` (`help/guide.html`): `GET /help/{set}/{guide}`, the guide with the set's other
//!   guides, its sections and the guides before and after it.
//! - `help.guide_image`: `GET /help/{set}/images/{file}`, an image of the set, kept by a browser for an
//!   hour.
//!
//! A set, a guide or an image the registry doesn't have is 404, and a visitor who isn't signed in goes
//! to the login.
//!
//! **Embedded.** Every guide and image is in the binary (`include_str!`, `include_bytes!`), as the
//! pages' other files are (`assets`), so the binary reads nothing from disk. ace3 reads them from its
//! checkout and renders a guide again when its file changes; here a guide is rendered once a process.
//! An image is looked up by its name in the set's list, so no path reaches a file system and ace3's
//! check that a path stays inside `images/` has nothing to check.
//!
//! **Rendering** ([`render_markdown`]), as ace3's `rendering.py` does over Python-Markdown, here over
//! pulldown-cmark (CommonMark with tables and GitHub's alerts):
//! - a link to another guide is written `users.md#section` and served as `users#section`;
//! - GitHub's alert syntax (`> [!TIP]`) becomes a callout block;
//! - an image links to itself, so one shrunk to the page's width opens at full size in a new tab;
//! - only absolute http(s) links open in a new tab;
//! - each section (`##`) and subsection (`###`) gets an id from its text, as Python-Markdown's `toc`
//!   makes it, and a link to itself, and they are the page's table of contents.
//!
//! What differs: raw HTML in a guide is shown as text, where ace3 passes it through. The guides have
//! none, and the pages' policy refuses inline styles and scripts, so the renderer writes none either: a
//! table's column alignment, which pulldown-cmark writes as a `style`, is dropped. The result is a
//! [`GuideHtml`], the second value askama doesn't escape (`ViewHtml` is the first), which only this
//! module makes, from the repository's own guides.
//!
//! Adding a guide is a Markdown file and an entry in [`GUIDE_SETS`]; `tests/gui.rs` checks that every
//! link, section and image a guide names is there, and that no image is left unused.

use std::fmt;
use std::sync::LazyLock;

use askama::Template;
use axum::extract::Path;
use axum::extract::rejection::PathRejection;
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use pulldown_cmark::{
    Alignment, BlockQuoteKind, CowStr, Event, HeadingLevel, Options, Parser, Tag, TagEnd, html,
};

use crate::session::{Failure, SignedIn, render, see_other};
use crate::templates::Layout;

/// How long a browser may keep a guide's image: ace3's `IMAGE_MAX_AGE_SECONDS`. An image changes
/// only with a new build, and then the guide is new too.
pub const IMAGE_MAX_AGE_SECONDS: u32 = 3600;

/// One guide of a set.
#[derive(Debug)]
pub struct Guide {
    pub slug: &'static str,
    pub title: &'static str,
    /// Who the guide is for, shown on the index.
    pub audience: &'static str,
    /// Its Markdown.
    pub source: &'static str,
}

/// An image of a set, by its name under `images/`.
#[derive(Debug)]
pub struct GuideImage {
    pub name: &'static str,
    pub bytes: &'static [u8],
    pub content_type: &'static str,
}

/// A set of guides: ace3's `GuideSet`.
#[derive(Debug)]
pub struct GuideSet {
    pub slug: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub guides: &'static [Guide],
    pub images: &'static [GuideImage],
}

impl GuideSet {
    pub fn guide(&self, slug: &str) -> Option<&'static Guide> {
        self.guides.iter().find(|guide| guide.slug == slug)
    }

    pub fn image(&self, name: &str) -> Option<&'static GuideImage> {
        self.images.iter().find(|image| image.name == name)
    }

    /// Where the set's first guide is, which a link to the set goes to.
    pub fn href(&self) -> String {
        format!("/help/{}/", self.slug)
    }
}

const SVG: &str = "image/svg+xml";
const PNG: &str = "image/png";

/// An SVS guide's image: a diagram (`.svg`) or a screenshot (`.png`), by its file's name.
macro_rules! svs_image {
    ($name:literal) => {
        GuideImage {
            name: $name,
            bytes: include_bytes!(concat!("../help/svs/images/", $name)),
            content_type: image_type($name),
        }
    };
}

/// The media type of an image, by its file's extension.
const fn image_type(name: &str) -> &'static str {
    match name.as_bytes() {
        [.., b'.', b's', b'v', b'g'] => SVG,
        [.., b'.', b'p', b'n', b'g'] => PNG,
        _ => panic!("a guide's image is an .svg or a .png"),
    }
}

/// The guide sets, in the index's order: ace3's `GUIDE_SETS`.
pub static GUIDE_SETS: &[GuideSet] = &[
    GuideSet {
        slug: "svs",
        title: "Signature Validation System (SVS)",
        description: "Testing ACE's detection signatures: YARA regression testing against graded samples, \
                  and Atomic Red Team runs that measure which ATT&CK techniques ACE detects.",
        guides: &[
            Guide {
                slug: "beginners",
                title: "Beginner's guide",
                audience: "New to ACE, or to signature validation and regression testing? Start here.",
                source: include_str!("../help/svs/beginners.md"),
            },
            Guide {
                slug: "users",
                title: "User's guide",
                audience: "For analysts who run atomics, review their results and write or fix \
                       signatures from them.",
                source: include_str!("../help/svs/users.md"),
            },
            Guide {
                slug: "administrators",
                title: "Administrator's guide",
                audience: "For ACE administrators who set SVS up and keep it running.",
                source: include_str!("../help/svs/administrators.md"),
            },
            Guide {
                slug: "developers",
                title: "Developer's guide",
                audience: "For developers who want to understand how SVS works, to improve it, build \
                       on it or fix it.",
                source: include_str!("../help/svs/developers.md"),
            },
        ],
        images: &[
            svs_image!("admin-components.svg"),
            svs_image!("alert-context.png"),
            svs_image!("alert-mismatch.png"),
            svs_image!("alert-page-test.png"),
            svs_image!("alert-partial.png"),
            svs_image!("alert-refused.png"),
            svs_image!("alert-test.png"),
            svs_image!("architecture.svg"),
            svs_image!("attribution.svg"),
            svs_image!("coverage-list.png"),
            svs_image!("coverage-technique.png"),
            svs_image!("help-index.png"),
            svs_image!("run-alerts.png"),
            svs_image!("run-comments.png"),
            svs_image!("run-error.png"),
            svs_image!("run-events.png"),
            svs_image!("run-failing-result.png"),
            svs_image!("run-history.png"),
            svs_image!("run-live.png"),
            svs_image!("run-needs-review.png"),
            svs_image!("run-result-candidates.png"),
            svs_image!("run-review-blockers.png"),
            svs_image!("run-reviewed.png"),
            svs_image!("run-states.svg"),
            svs_image!("runs-actions.png"),
            svs_image!("runs-batches.png"),
            svs_image!("runs-list.png"),
            svs_image!("runs-needs-attention.png"),
            svs_image!("sample-conflicted.png"),
            svs_image!("samples-list.png"),
            svs_image!("signatures-hub.png"),
            svs_image!("svs-loop.svg"),
            svs_image!("test-host-add.png"),
            svs_image!("test-hosts.png"),
            svs_image!("test-page.png"),
            svs_image!("tests-list.png"),
            svs_image!("validation-failed.png"),
            svs_image!("validation-new-fp.png"),
            svs_image!("validation-regression.png"),
            svs_image!("validations-list.png"),
            svs_image!("worklist-resolve.png"),
            svs_image!("worklist-signature.png"),
            svs_image!("worklist.png"),
            svs_image!("yara-qa.png"),
        ],
    },
    GuideSet {
        slug: "search",
        title: "Search",
        description: "Finding alerts: by the meaning of their text, by an indicator, a tag or an id named \
                  exactly, and the alerts like one you have open.",
        guides: &[Guide {
            slug: "query-language",
            title: "Searching alerts",
            audience: "For anyone using the search box on the alert list.",
            source: include_str!("../help/search/query-language.md"),
        }],
        images: &[],
    },
];

/// The SVS guides, which the SVS tabs and the signatures hub link to.
pub const SVS_GUIDES: &str = "/help/svs/";

pub fn guide_set(slug: &str) -> Option<&'static GuideSet> {
    GUIDE_SETS.iter().find(|set| set.slug == slug)
}

//
// rendering
//

/// A guide's HTML, which askama doesn't escape again. Only [`render_markdown`] makes one, from a
/// guide's Markdown, with any raw HTML in it written as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuideHtml(String);

impl GuideHtml {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GuideHtml {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl askama::filters::HtmlSafe for GuideHtml {}

/// A section of a guide, for the page's table of contents: ace3's `TocEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TocEntry {
    pub id: String,
    /// The heading's text.
    pub name: String,
    /// A section's subsections; a subsection has none.
    pub children: Vec<TocEntry>,
}

/// A rendered guide: ace3's `RenderedGuide`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedGuide {
    pub html: GuideHtml,
    /// The guide's sections (h2) and their subsections (h3).
    pub toc: Vec<TocEntry>,
}

/// A heading's id from its text, as Python-Markdown's `slugify` makes it: lower case, with everything
/// but letters, digits, `_`, `-` and white space dropped, and each run of white space and hyphens made
/// one hyphen. A character outside ASCII is dropped, as its `encode('ascii', 'ignore')` drops one that
/// has no ASCII form.
fn slugify(text: &str) -> String {
    let kept: String = text
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-') || c.is_ascii_whitespace())
        .collect();
    let mut slug = String::new();
    let mut gap = false;
    for c in kept.trim().chars() {
        if c == '-' || c.is_ascii_whitespace() {
            gap = true;
            continue;
        }
        if gap {
            slug.push('-');
            gap = false;
        }
        slug.push(c.to_ascii_lowercase());
    }
    if gap && !slug.is_empty() {
        slug.push('-');
    }
    slug
}

/// An id no earlier heading of the page has: Python-Markdown's `unique`, which adds `_1`, `_2`.
fn unique(slug: String, used: &mut Vec<String>) -> String {
    let mut id = slug.clone();
    let mut n = 0;
    while id.is_empty() || used.contains(&id) {
        n += 1;
        id = format!("{slug}_{n}");
    }
    used.push(id.clone());
    id
}

fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            c => escaped.push(c),
        }
    }
    escaped
}

/// A link to a sibling guide, `users.md` or `users.md#reviewing-a-run`, as it's served: without the
/// suffix. Anything else is None.
fn guide_link(href: &str) -> Option<String> {
    let (file, fragment) = match href.split_once('#') {
        Some((file, fragment)) => (file, Some(fragment)),
        None => (href, None),
    };
    let name = file.strip_suffix(".md")?;
    let named = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'));
    named.then(|| match fragment {
        Some(fragment) => format!("{name}#{fragment}"),
        None => name.to_owned(),
    })
}

fn callout_title(kind: BlockQuoteKind) -> (&'static str, &'static str) {
    match kind {
        BlockQuoteKind::Note => ("note", "Note"),
        BlockQuoteKind::Tip => ("tip", "Tip"),
        BlockQuoteKind::Important => ("important", "Important"),
        BlockQuoteKind::Warning => ("warning", "Warning"),
        BlockQuoteKind::Caution => ("caution", "Caution"),
    }
}

fn raw(html: String) -> Event<'static> {
    Event::Html(CowStr::from(html))
}

/// The text of the events inside a heading or an image: what a reader sees, without its markup.
fn plain(events: &[Event<'_>]) -> String {
    let mut text = String::new();
    for event in events {
        match event {
            Event::Text(part) | Event::Code(part) => text.push_str(part),
            Event::SoftBreak | Event::HardBreak => text.push(' '),
            _ => {}
        }
    }
    text
}

/// A guide's Markdown as the HTML its page shows, with its table of contents: ace3's
/// `render_markdown_guide`. The module's docs say what it does beyond CommonMark.
pub fn render_markdown(text: &str) -> RenderedGuide {
    let options = Options::ENABLE_TABLES | Options::ENABLE_GFM | Options::ENABLE_STRIKETHROUGH;
    let mut out: Vec<Event<'_>> = Vec::new();
    let mut toc: Vec<TocEntry> = Vec::new();
    let mut used: Vec<String> = Vec::new();
    // what's inside the heading or image being read, and where it began
    let mut held: Option<(Tag<'_>, Vec<Event<'_>>)> = None;
    // whether each open block quote is a callout
    let mut quotes: Vec<bool> = Vec::new();

    for event in Parser::new_ext(text, options) {
        // a guide's own HTML is text: the page writes none it didn't make
        let event = match event {
            Event::Html(html) | Event::InlineHtml(html) => Event::Text(html),
            other => other,
        };
        if let Some((tag, inner)) = held.as_mut() {
            let ends = matches!(
                (&*tag, &event),
                (Tag::Heading { .. }, Event::End(TagEnd::Heading(_)))
                    | (Tag::Image { .. }, Event::End(TagEnd::Image))
            );
            if !ends {
                inner.push(event);
                continue;
            }
            let Some((tag, inner)) = held.take() else {
                continue;
            };
            match tag {
                Tag::Heading { level, .. } => {
                    let name = plain(&inner);
                    let listed = matches!(level, HeadingLevel::H2 | HeadingLevel::H3);
                    if !listed {
                        out.push(raw(format!("<{level}>")));
                        out.extend(inner);
                        out.push(raw(format!("</{level}>\n")));
                        continue;
                    }
                    let id = unique(slugify(&name), &mut used);
                    out.push(raw(format!("<{level} id=\"{}\">", escape(&id))));
                    out.extend(inner);
                    out.push(raw(format!(
                        "<a class=\"help-anchor\" href=\"#{}\" title=\"Link to this section\">#</a></{level}>\n",
                        escape(&id)
                    )));
                    let entry = TocEntry {
                        id,
                        name,
                        children: Vec::new(),
                    };
                    match (level, toc.last_mut()) {
                        (HeadingLevel::H3, Some(section)) => section.children.push(entry),
                        // a subsection before any section has no section to sit under
                        (HeadingLevel::H3, None) => {}
                        _ => toc.push(entry),
                    }
                }
                Tag::Image { dest_url, .. } => {
                    let (src, alt) = (escape(&dest_url), escape(&plain(&inner)));
                    out.push(raw(format!(
                        "<a class=\"help-image\" href=\"{src}\" target=\"_blank\" \
                         title=\"Open the full-size image\"><img alt=\"{alt}\" src=\"{src}\"></a>"
                    )));
                }
                _ => {}
            }
            continue;
        }
        match event {
            Event::Start(tag @ (Tag::Heading { .. } | Tag::Image { .. })) => {
                held = Some((tag, Vec::new()));
            }
            Event::Start(Tag::Link {
                dest_url, title, ..
            }) => {
                let external = dest_url.starts_with("http://") || dest_url.starts_with("https://");
                let href = match guide_link(&dest_url) {
                    Some(guide) if !external => guide,
                    _ => dest_url.to_string(),
                };
                let mut link = format!("<a href=\"{}\"", escape(&href));
                if !title.is_empty() {
                    link.push_str(&format!(" title=\"{}\"", escape(&title)));
                }
                if external {
                    link.push_str(" rel=\"noopener noreferrer\" target=\"_blank\"");
                }
                link.push('>');
                out.push(raw(link));
            }
            Event::End(TagEnd::Link) => out.push(raw("</a>".to_owned())),
            Event::Start(Tag::BlockQuote(kind)) => {
                quotes.push(kind.is_some());
                match kind {
                    Some(kind) => {
                        let (class, title) = callout_title(kind);
                        out.push(raw(format!(
                            "<div class=\"help-callout help-callout-{class}\">\n\
                             <p class=\"help-callout-title\">{title}</p>\n"
                        )));
                    }
                    None => out.push(Event::Start(Tag::BlockQuote(None))),
                }
            }
            Event::End(TagEnd::BlockQuote(kind)) => {
                if quotes.pop().unwrap_or(false) {
                    out.push(raw("</div>\n".to_owned()));
                } else {
                    out.push(Event::End(TagEnd::BlockQuote(kind)));
                }
            }
            // a column's alignment would be an inline style, which the pages' policy refuses
            Event::Start(Tag::Table(columns)) => {
                out.push(Event::Start(Tag::Table(vec![
                    Alignment::None;
                    columns.len()
                ])));
            }
            other => out.push(other),
        }
    }
    let mut rendered = String::new();
    html::push_html(&mut rendered, out.into_iter());
    RenderedGuide {
        html: GuideHtml(rendered),
        toc,
    }
}

/// Every guide, rendered once, in the registry's order.
static RENDERED: LazyLock<Vec<Vec<RenderedGuide>>> = LazyLock::new(|| {
    GUIDE_SETS
        .iter()
        .map(|set| {
            set.guides
                .iter()
                .map(|guide| render_markdown(guide.source))
                .collect()
        })
        .collect()
});

/// The guide as its page shows it, or None for one the registry doesn't have.
pub fn rendered(set: &str, guide: &str) -> Option<&'static RenderedGuide> {
    let s = GUIDE_SETS.iter().position(|s| s.slug == set)?;
    let g = GUIDE_SETS[s].guides.iter().position(|g| g.slug == guide)?;
    RENDERED.get(s)?.get(g)
}

//
// the pages
//

/// `/help`, ace3's `help/index.html`.
#[derive(Debug, Template)]
#[template(path = "help/index.html")]
struct IndexPage {
    layout: Layout,
    sets: &'static [GuideSet],
}

/// `/help/{set}/{guide}`, ace3's `help/guide.html`.
#[derive(Debug, Template)]
#[template(path = "help/guide.html")]
struct GuidePage {
    layout: Layout,
    set: &'static GuideSet,
    guide: &'static Guide,
    rendered: &'static RenderedGuide,
    previous: Option<&'static Guide>,
    next: Option<&'static Guide>,
}

fn not_found(parts: &Parts) -> Response {
    Failure::new(StatusCode::NOT_FOUND, "no such guide", parts).into_response()
}

/// `GET /help`: every guide.
pub(crate) async fn index(viewer: SignedIn) -> Response {
    render(&IndexPage {
        layout: viewer.layout,
        sets: GUIDE_SETS,
    })
}

/// `GET /help/{set}` and `GET /help/{set}/`: the set's first guide.
pub(crate) async fn set_home(
    _viewer: SignedIn,
    parts: Parts,
    set: Result<Path<String>, PathRejection>,
) -> Response {
    let first = set
        .ok()
        .and_then(|Path(set)| guide_set(&set))
        .and_then(|set| Some((set, set.guides.first()?)));
    match first {
        Some((set, guide)) => see_other(&format!("/help/{}/{}", set.slug, guide.slug), None),
        None => not_found(&parts),
    }
}

/// `GET /help/{set}/{guide}`: a guide.
pub(crate) async fn guide(
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Response {
    let found = path.ok().and_then(|Path((set, guide))| {
        let set = guide_set(&set)?;
        let index = set.guides.iter().position(|g| g.slug == guide)?;
        Some((set, index, rendered(set.slug, &guide)?))
    });
    let Some((set, index, rendered)) = found else {
        return not_found(&parts);
    };
    render(&GuidePage {
        layout: viewer.layout,
        set,
        guide: &set.guides[index],
        rendered,
        previous: index.checked_sub(1).and_then(|i| set.guides.get(i)),
        next: set.guides.get(index + 1),
    })
}

/// `GET /help/{set}/images/{file}`: an image of the set.
pub(crate) async fn image(
    _viewer: SignedIn,
    parts: Parts,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Response {
    let found = path
        .ok()
        .and_then(|Path((set, file))| guide_set(&set)?.image(&file));
    let Some(image) = found else {
        return not_found(&parts);
    };
    let cache = format!("private, max-age={IMAGE_MAX_AGE_SECONDS}");
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(image.content_type),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_str(&cache).expect("a header value"),
            ),
        ],
        image.bytes,
    )
        .into_response()
}
