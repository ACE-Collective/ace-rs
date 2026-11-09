//! `urlfinderlib/finders/html.py`: `HtmlUrlFinder` and `HtmlTreeUrlFinder`, on libxml2's HTML
//! parser through `ace-lxml`, as urlfinderlib is on lxml's.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::sync::LazyLock;

use ace_lxml::{Document, LxmlError, Node};
use regex::Regex;

use crate::finders::text;
use crate::helpers::{self, fix_possible_url, fix_possible_value};
use crate::py::{self, PyErr, PyResult};
use crate::tokenizer::Tokenizer;
use crate::url::{Url, UrlList};

/// lxml's exception, as Python would see it.
fn lxml_error(e: LxmlError) -> PyErr {
    match e {
        LxmlError::NoDocument => PyErr::new("lxml.etree", "XMLSyntaxError", e.to_string()),
        LxmlError::Value(message) => PyErr::value_error(message),
        LxmlError::Memory => PyErr::builtin("MemoryError", ""),
    }
}

/// `HtmlUrlFinder(blob, base_url).find_urls()`: the text as it is and, if they differ, with its
/// entities and percent-encoding decoded.
pub fn find_urls(blob: &[u8], base_url: &str) -> PyResult<BTreeSet<String>> {
    let utf8 = helpers::remove_null_characters(&py::decode_utf8_ignore(blob)).into_owned();
    let decoded = py::html_unescape(&py::unquote(&utf8));
    let mut strings = vec![utf8.clone()];
    if decoded != utf8 {
        strings.push(decoded);
    }
    let mut urls = UrlList::new();
    for string in &strings {
        urls.extend(&TreeFinder::new(string, base_url)?.find_urls()?)?;
    }
    urls.distinct_values()
}

/// `_build_tree`: the document, with whatever followed its root moved into the root.
fn build_tree(string: &str) -> PyResult<Document> {
    let mut doc = Document::parse_html(string.as_bytes()).map_err(lxml_error)?;
    if doc.root().is_none() {
        doc = Document::parse_html(b"<html></html>").map_err(lxml_error)?;
    }
    if let Some(root) = doc.root() {
        for sibling in root.following_siblings() {
            root.append(sibling);
        }
    }
    Ok(doc)
}

/// `.//tag[@attr]` from the root, lazily, as ElementPath walks it.
fn descendants_with<'a>(
    root: Node<'a>,
    tag: &str,
    attrs: &'static [&'static str],
) -> impl Iterator<Item = Node<'a>> {
    root.iterdescendants(tag)
        .filter(move |node| attrs.iter().all(|attr| node.get(attr).is_some()))
}

fn space_class() -> &'static str {
    r"[\s\x1c-\x1f]"
}

static CSS_URL: LazyLock<Regex> = LazyLock::new(|| {
    let s = space_class();
    Regex::new(&format!(r#"(?i)url{s}*\({s}*['"]?(.*?)['"]?{s}*\)"#)).expect("a regex")
});
static DOCUMENT_WRITE: LazyLock<Regex> = LazyLock::new(|| {
    let s = space_class();
    Regex::new(&format!(r"(?i)document\.write{s}*\(.*?\){s}*;")).expect("a regex")
});
static WINDOW_LOCATION: LazyLock<Regex> = LazyLock::new(|| {
    let s = space_class();
    Regex::new(&format!(
        r#"(?i)window\.location\.href{s}*?={s}*?['"](.*?)['"]"#
    ))
    .expect("a regex")
});

/// `HtmlTreeUrlFinder`.
struct TreeFinder<'s> {
    string: &'s str,
    given_base_url: &'s str,
    /// `_base_url`: None until `base_url` is first asked for.
    base_url: RefCell<Option<String>>,
    tree: Document,
}

impl<'s> TreeFinder<'s> {
    fn new(string: &'s str, base_url: &'s str) -> PyResult<TreeFinder<'s>> {
        Ok(TreeFinder {
            string,
            given_base_url: base_url,
            base_url: RefCell::new(None),
            tree: build_tree(string)?,
        })
    }

    fn root(&self) -> Option<Node<'_>> {
        self.tree.root()
    }

    /// `base_url`: the document's `<base href>` if it's a URL, else the one given.
    fn base_url(&self) -> PyResult<String> {
        if let Some(base) = self.base_url.borrow().as_ref() {
            return Ok(base.clone());
        }
        let found = self.base_url_from_html()?;
        let base = if found.is_empty() {
            self.given_base_url.to_owned()
        } else {
            found
        };
        *self.base_url.borrow_mut() = Some(base.clone());
        Ok(base)
    }

    fn base_url_from_html(&self) -> PyResult<String> {
        let Some(root) = self.root() else {
            return Ok(String::new());
        };
        let Some(tag) = descendants_with(root, "base", &["href"]).next() else {
            return Ok(String::new());
        };
        let base = fix_possible_url(&tag.get("href").unwrap_or_default(), false);
        Ok(if Url::new(&base).is_url()? {
            base
        } else {
            String::new()
        })
    }

    fn find_urls(&self) -> PyResult<BTreeSet<String>> {
        let mut valid = UrlList::new();
        for url in self.find_document_write_urls()? {
            valid.append(&url)?;
        }
        for url in self.window_location_href() {
            valid.append(&fix_possible_url(&url, false))?;
        }
        for url in self.find_visible_urls()? {
            valid.append(&url)?;
        }
        for value in self.meta_refresh_values() {
            valid.append(&value)?;
        }

        let mut possible: BTreeSet<String> = BTreeSet::new();
        let eligible = self.base_url_eligible_values()?;
        for value in &eligible {
            possible.insert(py::urljoin(&self.base_url()?, value)?);
        }
        let srcset = self.srcset_values();
        let raw_base = self.base_url.borrow().clone().unwrap_or_default();
        for value in &srcset {
            possible.insert(py::urljoin(&raw_base, value)?);
        }
        possible.extend(self.tag_attribute_values());
        for value in &possible {
            valid.append(&fix_possible_url(value, false))?;
        }

        let tree_string = py::unquote(&self.tree.tostring_html().map_err(lxml_error)?).into_owned();
        let tok = Tokenizer::new(tree_string.as_bytes());
        for (open, close) in [
            ("\"http", "\""),
            ("\"ftp", "\""),
            ("'http", "'"),
            ("'ftp", "'"),
            ("\"HTTP", "\""),
            ("\"FTP", "\""),
            ("'HTTP", "'"),
            ("'FTP", "'"),
        ] {
            for token in tok.between_open_and_close(open, close) {
                valid.append(token)?;
            }
        }
        valid.distinct_values()
    }

    fn find_document_write_urls(&self) -> PyResult<BTreeSet<String>> {
        let mut urls = UrlList::new();
        for content in self.document_write_contents() {
            let base = self.base_url()?;
            urls.extend(&find_urls(content.as_bytes(), &base)?)?;
        }
        urls.distinct_values()
    }

    fn document_write_contents(&self) -> BTreeSet<String> {
        let writes: BTreeSet<&str> = DOCUMENT_WRITE
            .find_iter(self.string)
            .map(|m| m.as_str())
            .collect();
        writes
            .into_iter()
            .map(|write| {
                // write[rfind("(") + 1 : find(")")]
                let begin = write.rfind('(').map_or(0, |i| i + 1);
                let end = write.find(')').unwrap_or(write.len());
                let content = if begin <= end { &write[begin..end] } else { "" };
                fix_possible_value(content)
            })
            .filter(|content| !content.is_empty())
            .collect()
    }

    fn find_visible_urls(&self) -> PyResult<BTreeSet<String>> {
        let visible = self.visible_text()?;
        let possible: BTreeSet<&str> = py::splitlines(&visible)
            .into_iter()
            .filter(|line| line.contains('.') && line.contains('/'))
            .collect();
        let mut urls = UrlList::new();
        for line in possible {
            urls.extend(&text::find_urls(line.as_bytes(), false)?)?;
        }
        urls.distinct_values()
    }

    /// `_get_visible_text`: a fresh tree without obfuscating fonts, scripts and styles, as text.
    fn visible_text(&self) -> PyResult<String> {
        let tree = build_tree(self.string)?;
        if let Some(root) = tree.root() {
            for tag in descendants_with(root, "font", &["id"]) {
                if tag.items().len() == 1 {
                    remove_element(tag)?;
                }
            }
            for name in ["script", "style"] {
                for tag in root.iterdescendants(name) {
                    remove_element(tag)?;
                }
            }
        }
        let text = tree.tostring_text().map_err(lxml_error)?;
        Ok(py::strip(&py::decode_utf8_ignore(&text)).to_owned())
    }

    /// `_get_action_values` and its likes: the attribute fixed, then blanked.
    fn attribute_values(&self, attr: &'static str) -> PyResult<BTreeSet<String>> {
        let mut values = BTreeSet::new();
        let Some(root) = self.root() else {
            return Ok(values);
        };
        let attrs: &'static [&'static str] = match attr {
            "action" => &["action"],
            "background" => &["background"],
            "href" => &["href"],
            _ => &["src"],
        };
        for tag in descendants_with(root, "*", attrs) {
            let value = tag.get(attr).unwrap_or_default();
            if self.base_url()?.is_empty() {
                values.insert(fix_possible_url(&value, false));
            } else {
                values.insert(fix_possible_value(&value));
            }
            tag.set(attr, "").map_err(lxml_error)?;
        }
        Ok(values)
    }

    fn base_url_eligible_values(&self) -> PyResult<BTreeSet<String>> {
        let mut values = self.attribute_values("action")?;
        values.extend(self.attribute_values("background")?);
        values.extend(
            CSS_URL
                .captures_iter(self.string)
                .map(|c| c.get(1).map_or("", |m| m.as_str()).to_owned()),
        );
        values.extend(self.attribute_values("href")?);
        values.extend(self.attribute_values("src")?);
        values.extend(self.xmlns_values());
        Ok(values)
    }

    fn xmlns_values(&self) -> BTreeSet<String> {
        let mut values = BTreeSet::new();
        let Some(root) = self.root() else {
            return values;
        };
        if let Some(xmlns) = root.get("xmlns") {
            values.insert(fix_possible_url(&xmlns, false));
        }
        for tag in descendants_with(root, "*", &["xmlns"]) {
            values.insert(fix_possible_url(
                &tag.get("xmlns").unwrap_or_default(),
                false,
            ));
        }
        values
    }

    fn meta_refresh_values(&self) -> BTreeSet<String> {
        let mut values = BTreeSet::new();
        let Some(root) = self.root() else {
            return values;
        };
        for tag in descendants_with(root, "meta", &["http-equiv", "content"]) {
            let value = tag.get("content").unwrap_or_default();
            if py::lower(&value).contains("url=") {
                let after = value.split_once('=').map_or("", |(_, after)| after);
                values.insert(fix_possible_value(py::strip(after)));
            }
        }
        values
    }

    fn srcset_values(&self) -> BTreeSet<String> {
        let mut values = BTreeSet::new();
        let Some(root) = self.root() else {
            return values;
        };
        for tag in descendants_with(root, "*", &["srcset"]) {
            let value = fix_possible_url(&tag.get("srcset").unwrap_or_default(), false);
            for split in value.split(',') {
                let stripped = py::strip(split);
                if !stripped.is_empty() {
                    values.insert(stripped.split(' ').next().unwrap_or("").to_owned());
                }
            }
            // setting a plain name to "" doesn't raise
            if tag.set("srcset", "").is_err() {
                continue;
            }
        }
        values
    }

    /// `_get_tag_attribute_values`: every attribute's value, then every attribute but onclick
    /// blanked, where lxml lets it be set.
    fn tag_attribute_values(&self) -> BTreeSet<String> {
        let mut values = BTreeSet::new();
        let Some(root) = self.root() else {
            return values;
        };
        for element in root.iter() {
            values.extend(element.values());
            for attr in element.keys() {
                if py::lower(&attr) == "onclick" {
                    continue;
                }
                // lxml refuses some names it parsed; the value was already taken
                if element.set(&attr, "").is_err() {
                    continue;
                }
            }
        }
        values
    }

    fn window_location_href(&self) -> BTreeSet<String> {
        WINDOW_LOCATION
            .captures_iter(self.string)
            .map(|c| c.get(1).map_or("", |m| m.as_str()).to_owned())
            .collect()
    }
}

/// `_remove_element_from_tree`: the element goes, and its tail stays if it holds more than
/// whitespace.
fn remove_element(element: Node<'_>) -> PyResult<()> {
    let parent = element
        .getparent()
        .ok_or_else(|| PyErr::builtin("AttributeError", "'NoneType' object has no attribute"))?;
    if let Some(tail) = element.tail()
        && !py::strip(&tail).is_empty()
    {
        match element.getprevious() {
            Some(prev) => {
                let text = format!("{}{tail}", prev.tail().unwrap_or_default());
                prev.set_tail(Some(&text)).map_err(lxml_error)?;
            }
            None => {
                let text = format!("{}{tail}", parent.text().unwrap_or_default());
                parent.set_text(Some(&text)).map_err(lxml_error)?;
            }
        }
    }
    parent.remove(element).map_err(lxml_error)
}
