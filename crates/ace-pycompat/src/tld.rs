//! The tld package 0.13.2: `get_tld` and `get_fld`, with the Public Suffix List it bundles.
//!
//! `src/tld/effective_tld_names.dat.txt` is tld's `res/effective_tld_names.dat.txt`, byte for byte
//! (Mozilla Public License 2.0). It is read as tld reads it, quirks included: a `// xn--` comment
//! line adds its second word as a rule, a `!` rule sets its parent's one exception (a later one
//! replaces it) and makes the parent a leaf, and `search_private=False` uses a list that stops at
//! the private section, as tld's public-only parser does. Errors are `tld.exceptions.TldBadUrl` and
//! `TldDomainNotFound` (both `ValueError`s), `TldImproperlyConfigured`, and urlsplit's `ValueError`.

use crate::PyErr;
use crate::parse::{SplitResult, urlsplit};
use crate::pystr::lower;

/// A node of a trie `build.rs` wrote: its children are `edges[first..first + count]`, sorted by
/// label.
struct Node {
    first: u32,
    count: u32,
    exception: Option<&'static str>,
    leaf: bool,
    private: bool,
}

struct Trie {
    nodes: &'static [Node],
    edges: &'static [(&'static str, u32)],
}

impl Trie {
    fn root(&self) -> &Node {
        &self.nodes[0]
    }

    fn children(&self, node: &Node) -> &[(&'static str, u32)] {
        &self.edges[node.first as usize..(node.first + node.count) as usize]
    }

    fn child(&self, node: &Node, label: &str) -> Option<&Node> {
        let children = self.children(node);
        let at = children.binary_search_by(|(l, _)| (*l).cmp(label)).ok()?;
        Some(&self.nodes[children[at].1 as usize])
    }
}

// FULL and PUBLIC_ONLY, read from the list when the crate is built: a fresh process would
// otherwise spend about 2 ms building a trie before its first lookup.
include!(concat!(env!("OUT_DIR"), "/tld_tries.rs"));

/// tld's `Result` for `as_object=True`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TldResult {
    pub subdomain: String,
    /// The registrable label, or the tld when there is none, as `Result.__init__` sets it.
    pub domain: String,
    pub tld: String,
    pub fld: String,
    pub parsed_url: SplitResult,
}

struct Processed {
    domain_parts: Vec<String>,
    non_zero_i: isize,
    parsed_url: SplitResult,
}

fn exc(kind: &'static str, message: String) -> PyErr {
    PyErr::new("tld.exceptions", kind, message)
}

/// `re.match(r"^[a-z0-9.+:-]*//", s)`.
fn has_protocol(s: &str) -> bool {
    let rest = s.trim_start_matches(|c: char| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '+' | ':' | '-')
    });
    rest.starts_with("//")
}

fn process_url(
    url: &str,
    fail_silently: bool,
    fix_protocol: bool,
    search_public: bool,
    search_private: bool,
) -> Result<Option<Processed>, PyErr> {
    if !(search_public || search_private) {
        return Err(exc(
            "TldImproperlyConfigured",
            "Either `search_public` or `search_private` (or both) shall be set to True.".to_owned(),
        ));
    }
    let fixed;
    let url = if fix_protocol && !has_protocol(&lower(url)) {
        fixed = format!("https://{url}");
        fixed.as_str()
    } else {
        url
    };
    let parsed_url = match urlsplit(url, "", true) {
        Ok(p) => p,
        Err(_) if fail_silently => return Ok(None),
        Err(e) => return Err(e),
    };
    process_split(
        url,
        parsed_url,
        fail_silently,
        search_public,
        search_private,
    )
}

/// `process_url` from its `urlsplit`, which is what it does when given a `SplitResult`.
fn process_split(
    url: &str,
    parsed_url: SplitResult,
    fail_silently: bool,
    search_public: bool,
    search_private: bool,
) -> Result<Option<Processed>, PyErr> {
    let trie = if search_private { &FULL } else { &PUBLIC_ONLY };
    let Some(domain_name) = parsed_url.hostname().filter(|h| !h.is_empty()) else {
        if fail_silently {
            return Ok(None);
        }
        return Err(exc("TldBadUrl", format!("Is not a valid URL {url}!")));
    };
    let mut domain_name = lower(&domain_name).into_owned();
    if domain_name.ends_with('.') {
        domain_name.truncate(domain_name.trim_end_matches('.').len());
    }
    let domain_parts: Vec<String> = domain_name.split('.').map(str::to_owned).collect();
    let mut node = trie.root();
    let mut current_length = 0;
    let mut tld_length = 0;
    let mut matched: Option<&Node> = None;
    for part in domain_parts.iter().rev() {
        if node.count == 0 || node.exception == Some(part.as_str()) {
            break;
        }
        let Some(child) = trie.child(node, part).or_else(|| trie.child(node, "*")) else {
            break;
        };
        current_length += 1;
        node = child;
        if node.leaf {
            tld_length = current_length;
            matched = Some(node);
        }
    }
    let found = matched
        .is_some_and(|m| m.leaf && (search_public || m.private) && (search_private || !m.private));
    if !found {
        if fail_silently {
            return Ok(None);
        }
        return Err(exc(
            "TldDomainNotFound",
            format!("Domain {domain_name} didn't match any existing TLD name!"),
        ));
    }
    let len = domain_parts.len();
    let non_zero_i = if len == tld_length {
        -1
    } else {
        (len - tld_length).max(1) as isize
    };
    Ok(Some(Processed {
        domain_parts,
        non_zero_i,
        parsed_url,
    }))
}

/// `tld.get_tld(split, fail_silently=True)` for a `SplitResult` already made, as urlfinderlib's
/// `is_netloc_valid_tld` gets for its own value: `urlsplit` doesn't run again.
pub fn get_tld_of_split(split: &SplitResult) -> Option<String> {
    // the hostname is all process_url reads of it
    let host_only = SplitResult {
        netloc: split.netloc.clone(),
        ..SplitResult::default()
    };
    let p = process_split("", host_only, true, true, true).ok()??;
    if p.non_zero_i < 0 {
        return p.parsed_url.hostname();
    }
    Some(p.domain_parts[p.non_zero_i as usize..].join("."))
}

/// `tld.get_tld(url, fail_silently, as_object=False, fix_protocol, search_public, search_private)`.
pub fn get_tld(
    url: &str,
    fail_silently: bool,
    fix_protocol: bool,
    search_public: bool,
    search_private: bool,
) -> Result<Option<String>, PyErr> {
    let Some(p) = process_url(
        url,
        fail_silently,
        fix_protocol,
        search_public,
        search_private,
    )?
    else {
        return Ok(None);
    };
    if p.non_zero_i < 0 {
        return Ok(p.parsed_url.hostname());
    }
    Ok(Some(p.domain_parts[p.non_zero_i as usize..].join(".")))
}

/// `tld.get_tld(url, fail_silently, as_object=True, fix_protocol, search_public, search_private)`.
pub fn get_tld_object(
    url: &str,
    fail_silently: bool,
    fix_protocol: bool,
    search_public: bool,
    search_private: bool,
) -> Result<Option<TldResult>, PyErr> {
    let Some(p) = process_url(
        url,
        fail_silently,
        fix_protocol,
        search_public,
        search_private,
    )?
    else {
        return Ok(None);
    };
    let (subdomain, domain, tld) = if p.non_zero_i < 0 {
        (
            String::new(),
            String::new(),
            p.parsed_url.hostname().unwrap_or_default(),
        )
    } else {
        let i = p.non_zero_i as usize;
        (
            p.domain_parts[..i - 1].join("."),
            p.domain_parts[i - 1..i].join("."),
            p.domain_parts[i..].join("."),
        )
    };
    let (domain, fld) = if domain.is_empty() {
        (tld.clone(), tld.clone())
    } else {
        let fld = format!("{domain}.{tld}");
        (domain, fld)
    };
    Ok(Some(TldResult {
        subdomain,
        domain,
        tld,
        fld,
        parsed_url: p.parsed_url,
    }))
}

/// `tld.get_fld(url, fail_silently, fix_protocol, search_public, search_private)`.
pub fn get_fld(
    url: &str,
    fail_silently: bool,
    fix_protocol: bool,
    search_public: bool,
    search_private: bool,
) -> Result<Option<String>, PyErr> {
    let Some(p) = process_url(
        url,
        fail_silently,
        fix_protocol,
        search_public,
        search_private,
    )?
    else {
        return Ok(None);
    };
    if p.non_zero_i < 0 {
        return Ok(p.parsed_url.hostname());
    }
    Ok(Some(p.domain_parts[p.non_zero_i as usize - 1..].join(".")))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use std::collections::HashMap;

    use super::*;
    use crate::pystr::{is_space, splitlines_keepends, strip};
    use crate::testdata::{Mismatches, outcome, s};

    /// A node of the trie as tld builds it at run time, which `build.rs` has to reproduce.
    #[derive(Default)]
    struct Loaded {
        children: HashMap<String, usize>,
        exception: Option<String>,
        leaf: bool,
        private: bool,
    }

    /// `BaseMozillaTLDSourceParser.get_tld_names`, read with `pystr`'s Python string functions.
    fn load(include_private: bool) -> Vec<Loaded> {
        let mut nodes = vec![Loaded::default()];
        let mut private_section = false;
        for line in splitlines_keepends(include_str!("tld/effective_tld_names.dat.txt")) {
            if line.contains("===BEGIN PRIVATE DOMAINS===") {
                private_section = true;
            }
            if private_section && !include_private {
                break;
            }
            let mut line = line;
            if line.contains("// xn--") {
                line = line
                    .split(is_space)
                    .filter(|w| !w.is_empty())
                    .nth(1)
                    .unwrap_or("");
            }
            if line.starts_with(['/', '\n']) {
                continue;
            }
            let mut node = 0;
            for part in strip(line).split('.').rev() {
                if let Some(exception) = part.strip_prefix('!') {
                    nodes[node].exception = Some(exception.to_owned());
                    break;
                }
                node = match nodes[node].children.get(part) {
                    Some(&child) => child,
                    None => {
                        nodes.push(Loaded::default());
                        let child = nodes.len() - 1;
                        nodes[node].children.insert(part.to_owned(), child);
                        child
                    }
                };
            }
            nodes[node].leaf = true;
            nodes[node].private |= private_section;
        }
        nodes
    }

    /// Walks both tries from the root, looking each label up as `process_split` does, and returns
    /// how many nodes it compared.
    fn compare(trie: &Trie, loaded: &[Loaded]) -> usize {
        let mut stack = vec![(trie.root(), 0, String::new())];
        let mut seen = 0;
        while let Some((node, at, path)) = stack.pop() {
            let want = &loaded[at];
            assert_eq!(
                node.exception,
                want.exception.as_deref(),
                "exception at {path:?}"
            );
            assert_eq!(node.leaf, want.leaf, "leaf at {path:?}");
            assert_eq!(node.private, want.private, "private at {path:?}");
            assert_eq!(
                node.count as usize,
                want.children.len(),
                "children at {path:?}"
            );
            for (label, &child) in &want.children {
                let found = trie
                    .child(node, label)
                    .unwrap_or_else(|| panic!("{label:?} under {path:?} isn't found"));
                stack.push((found, child, format!("{label}.{path}")));
            }
            seen += 1;
        }
        assert_eq!(seen, trie.nodes.len(), "nodes no label reaches");
        seen
    }

    #[test]
    fn the_static_tries_are_the_ones_tld_builds() {
        let full = compare(&FULL, &load(true));
        let public = compare(&PUBLIC_ONLY, &load(false));
        // the private section adds rules, so a count that didn't grow means it was left out
        assert!(
            public > 5000 && full > public,
            "{public} public, {full} full"
        );
    }

    #[test]
    fn get_tld_matches_python() {
        let data: Value = crate::testdata::load("tld", include_str!("../tests/data/tld.json"));
        let mut m = Mismatches::new("tld");
        for case in data.as_array().unwrap() {
            let u = s(case, "url");
            let flags: Vec<bool> = case["flags"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_bool().unwrap())
                .collect();
            let (fs, fp, sp, spr) = (flags[0], flags[1], flags[2], flags[3]);
            let obj = outcome(get_tld_object(u, fs, fp, sp, spr), |r| {
                json!(r.map(|r| {
                    let p = &r.parsed_url;
                    json!([
                        r.subdomain,
                        r.domain,
                        r.tld,
                        r.fld,
                        [p.scheme, p.netloc, p.path, p.query, p.fragment]
                    ])
                }))
            });
            let got = json!({
                "url": u, "flags": flags,
                "obj": obj,
                "str": outcome(get_tld(u, fs, fp, sp, spr), |v| json!(v)),
                "fld": outcome(get_fld(u, fs, fp, sp, spr), |v| json!(v)),
            });
            m.check((u, &flags), &got, case);
        }
        m.finish();
    }
}
