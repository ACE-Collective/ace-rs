//! What `html_js_extraction.py` shares with `har.py`: parsing a document as BeautifulSoup does,
//! finding a script's source, and the DOM snapshot the JavaScript deobfuscator reads.

use std::collections::BTreeMap;

use ace_lxml::soup::Tree;
use ace_pycompat::pystr;
use ace_results::types::html::{DomElement, DomSnapshot, DomSnapshotFile};

use crate::py::{json_str_len, truncate_chars};

/// `DOM_SNAPSHOT_MAX_BYTES`, the default `dom_snapshot_max_bytes`.
pub const DOM_SNAPSHOT_MAX_BYTES: usize = 524_288;
const DOM_SNAPSHOT_MAX_ELEMENTS: usize = 2000;
const DOM_SNAPSHOT_MAX_ATTR_LEN: usize = 16_384;
const DOM_SNAPSHOT_MAX_TEXT_LEN: usize = 4096;
const DOM_SNAPSHOT_SKIP_TAGS: [&str; 2] = ["script", "style"];

/// The snapshots one result keeps, in JSON bytes. ace3 writes each to a file; here they ride in
/// the result, so past this many bytes a document's snapshot is neither kept nor listed.
pub const MAX_KEPT_SNAPSHOT_BYTES: usize = 16 << 20;

/// `SCRIPT_SOURCE_ATTRIBUTES`.
const SCRIPT_SOURCE_ATTRIBUTES: [&str; 3] = ["src", "href", "xlink:href"];

/// `parse_document(html)`: None where BeautifulSoup raises.
pub fn parse_document(html: &str) -> Option<Tree> {
    ace_lxml::soup::parse(html)
}

/// `get_script_source(script)`: the first of `src`, `href` and `xlink:href` it has, None for an
/// inline script.
pub fn get_script_source(tree: &Tree, script: usize) -> Option<String> {
    SCRIPT_SOURCE_ATTRIBUTES
        .iter()
        .find_map(|attr| tree.get(script, attr))
        .map(|value| value.joined())
}

/// The length of `json.dumps(element, separators=(",", ":"))`.
fn element_json_len(element: &DomElement, attrs: &[(String, String)]) -> usize {
    // {"tag":<tag>,"attrs":{<k>:<v>,...}} and ,"text":<text> before the last brace
    let mut len = r#"{"tag":"#.len() + json_str_len(&element.tag) + r#","attrs":{"#.len();
    for (i, (name, value)) in attrs.iter().enumerate() {
        len += usize::from(i > 0) + json_str_len(name) + 1 + json_str_len(value);
    }
    len += "}".len();
    if let Some(text) = &element.text {
        len += r#","text":"#.len() + json_str_len(text);
    }
    len + "}".len()
}

/// `build_dom_snapshot(soup, max_bytes, url)`: each element but scripts and styles, up to 2000
/// and `max_bytes` of JSON, with its attributes and its first own string. None when no element
/// survives.
pub fn build_dom_snapshot(tree: &Tree, max_bytes: usize, url: Option<&str>) -> Option<DomSnapshot> {
    let mut elements = Vec::new();
    let mut truncated = false;
    let mut total = 0usize;
    for tag in tree.elements() {
        let name = tree.name(tag).unwrap_or_default();
        if DOM_SNAPSHOT_SKIP_TAGS.contains(&name) {
            continue;
        }
        if elements.len() >= DOM_SNAPSHOT_MAX_ELEMENTS {
            truncated = true;
            break;
        }
        // a dict, so a name given twice is in it once, where it was first
        let mut attrs: Vec<(String, String)> = Vec::new();
        for (attr, value) in tree.attrs(tag) {
            let mut value = value.joined();
            if let Some(cut) = truncate_chars(&value, DOM_SNAPSHOT_MAX_ATTR_LEN) {
                value = cut.to_owned();
                truncated = true;
            }
            match attrs.iter_mut().find(|(n, _)| n == attr) {
                Some(slot) => slot.1 = value,
                None => attrs.push((attr.clone(), value)),
            }
        }
        let mut element = DomElement {
            tag: name.to_owned(),
            attrs: BTreeMap::new(),
            text: None,
        };
        if let Some(own) = tree.own_string(tag)
            && !own.is_empty()
        {
            let mut text = pystr::strip(own);
            if !text.is_empty() {
                if let Some(cut) = truncate_chars(text, DOM_SNAPSHOT_MAX_TEXT_LEN) {
                    text = cut;
                    truncated = true;
                }
                element.text = Some(text.to_owned());
            }
        }
        total += element_json_len(&element, &attrs);
        if total > max_bytes {
            truncated = true;
            break;
        }
        element.attrs = attrs.into_iter().collect();
        elements.push(element);
    }
    if elements.is_empty() {
        return None;
    }
    Some(DomSnapshot {
        version: 1,
        truncated,
        elements,
        url: url.map(str::to_owned),
    })
}

/// The length of `json.dumps(snapshot, separators=(",", ":"))`, which ace3 writes to the
/// sidecar.
pub fn snapshot_json_len(snapshot: &DomSnapshot) -> usize {
    let mut len = r#"{"version":1,"truncated":"#.len()
        + if snapshot.truncated { 4 } else { 5 }
        + r#","elements":["#.len()
        + "]}".len();
    for (i, element) in snapshot.elements.iter().enumerate() {
        let attrs: Vec<(String, String)> = element
            .attrs
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        len += usize::from(i > 0) + element_json_len(element, &attrs);
    }
    if let Some(url) = &snapshot.url {
        len += r#","url":"#.len() + json_str_len(url);
    }
    len
}

/// The sidecars a result writes: each snapshot once, with the files it's the sidecar of.
#[derive(Debug, Default)]
pub struct Sidecars {
    snapshots: Vec<DomSnapshotFile>,
    kept_bytes: usize,
}

/// A snapshot as [`Sidecars`] holds it: the index of a kept one, or one past the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kept {
    At(usize),
    Over,
}

impl Sidecars {
    /// Keeps `snapshot` if it fits, for the files later given to [`Sidecars::write`].
    pub fn keep(&mut self, snapshot: DomSnapshot) -> Kept {
        let len = snapshot_json_len(&snapshot);
        if self.kept_bytes + len > MAX_KEPT_SNAPSHOT_BYTES {
            return Kept::Over;
        }
        self.kept_bytes += len;
        self.snapshots.push(DomSnapshotFile {
            files: Vec::new(),
            snapshot,
        });
        Kept::At(self.snapshots.len() - 1)
    }

    /// `write_dom_snapshot(<file>.dom.json, snapshot)`: the file's sidecar is now this snapshot,
    /// in place of any it had. False when the snapshot wasn't kept, as for a write that failed.
    pub fn write(&mut self, file: &str, kept: Kept) -> bool {
        let Kept::At(index) = kept else {
            return false;
        };
        for other in &mut self.snapshots {
            other.files.retain(|f| f != file);
        }
        self.snapshots[index].files.push(file.to_owned());
        true
    }

    /// The snapshots some file still has as its sidecar.
    pub fn into_files(self) -> Vec<DomSnapshotFile> {
        self.snapshots
            .into_iter()
            .filter(|s| !s.files.is_empty())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn python_dumps_len(snapshot: &DomSnapshot) -> usize {
        // serde_json without escapes beyond ensure_ascii's, for ASCII text with no controls
        serde_json::to_string(snapshot).expect("serializes").len()
    }

    #[test]
    fn snapshot_lengths_match_the_json() {
        let tree = parse_document(
            r#"<html><body><div id="d" class=" a  b " data-u="https://x.example/?a=1">hi <b>x</b></div><script>s</script><p>"q"</p></body></html>"#,
        )
        .expect("parses");
        let snapshot =
            build_dom_snapshot(&tree, DOM_SNAPSHOT_MAX_BYTES, Some("https://x.example/"))
                .expect("a snapshot");
        assert_eq!(snapshot.elements.len(), 5);
        assert_eq!(snapshot.elements[2].attrs["class"], "a b");
        assert_eq!(snapshot.elements[2].text.as_deref(), Some("hi"));
        assert_eq!(snapshot_json_len(&snapshot), python_dumps_len(&snapshot));
        let small = build_dom_snapshot(&tree, 60, None).expect("a snapshot");
        assert!(small.truncated);
        assert_eq!(small.elements.len(), 2);
    }

    #[test]
    fn a_file_s_sidecar_is_the_last_written() {
        let tree = parse_document("<p>a</p>").expect("parses");
        let snapshot = build_dom_snapshot(&tree, DOM_SNAPSHOT_MAX_BYTES, None).expect("a snapshot");
        let mut sidecars = Sidecars::default();
        let first = sidecars.keep(snapshot.clone());
        let second = sidecars.keep(snapshot);
        assert!(sidecars.write("page.html", first));
        assert!(sidecars.write("a.js", first));
        assert!(sidecars.write("page.html", second));
        let files = sidecars.into_files();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].files, ["a.js"]);
        assert_eq!(files[1].files, ["page.html"]);
        assert!(!Sidecars::default().write("x", Kept::Over));
    }
}
