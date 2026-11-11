//! The root's tree as a module that reads it gets it on the lease (`Module::READS_TREE`), for the
//! modules that walk the tree as ace3's do: its observables, the results on each, what each result
//! added, and the tasks still to finish.
//!
//! ace3's modules hold the whole `RootAnalysis` and walk it with `recurse_tree`, `search_down`,
//! `get_observables_by_type` and `wait_for_analysis`. A parser's task process has no channel back
//! to the core while it runs, so the core sends the tree, as it is when the task is leased, with the
//! task. Results are referred to by module and analysis type, not details: a module reads its own
//! observable's results from the modules it depends on as it always has (`Module::DEPENDS_ON`).
//! A file whose bytes a module reads (`Module::READS_TREE_FILES`) comes with a download, which the
//! pool fetches before the task runs (`TaskContext::tree_file`).

use ace_results::{ObservableKind, ObservableRef};
use serde::{Deserialize, Serialize};

use crate::wire::Presigned;

/// The most observables and the most results the core sends. A root past either is cut, in the
/// order its observables and results were added, and says so (`TreeView::truncated`).
pub const MAX_TREE_OBSERVABLES: usize = 20_000;
pub const MAX_TREE_RESULTS: usize = 20_000;

/// The files of the tree whose bytes a module reads (`Module::READS_TREE_FILES`): those no larger
/// than `max_size` added under a path whose last part contains one of `names_containing`, or
/// tagged `tagged`, such as the TLS key logs tls_keylog tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeFiles {
    pub names_containing: &'static [&'static str],
    pub max_size: u64,
    pub tagged: Option<&'static str>,
}

impl TreeFiles {
    /// Whether the core sends the file added under `path`, of `size` bytes, with `tags`.
    pub fn wants(&self, path: &str, size: u64, tags: &[String]) -> bool {
        let name = path.rsplit('/').next().unwrap_or_default();
        size <= self.max_size
            && (self.names_containing.iter().any(|part| name.contains(part))
                || self.tagged.is_some_and(|tag| tags.iter().any(|t| t == tag)))
    }
}

/// The root's tree when the task was leased.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeView {
    /// What the root's submitter said its alert type is, as ace3's `alert_type`, such as `mailbox`.
    /// None when it said nothing: only a submitter inside ACE says one.
    #[serde(default)]
    pub alert_type: Option<String>,
    /// An observable in the root is whitelisted, as ace3's `RootAnalysis.whitelisted`.
    #[serde(default)]
    pub whitelisted: bool,
    /// The task's own observable, by its index in `observables`.
    pub this: usize,
    /// The root's observables, in the order they were added.
    pub observables: Vec<TreeObservable>,
    /// The root's results, in the order they landed.
    pub results: Vec<TreeResult>,
    /// The root had more observables or results than the core sends.
    #[serde(default)]
    pub truncated: bool,
}

/// One observable of the tree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeObservable {
    #[serde(rename = "type")]
    pub kind: ObservableKind,
    /// A file's is its sha256.
    pub value: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub directives: Vec<String>,
    /// How many detection points it has.
    #[serde(default)]
    pub detections: u32,
    /// A file's paths, each with its `yara_meta` types, in the order they were added.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<TreePath>,
    /// A file's size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// The modules with a task on it that hasn't finished: queued, delayed or running.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending: Vec<String>,
    /// Where to download a file the module reads (`Module::READS_TREE_FILES`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download: Option<Presigned>,
}

/// A path a file was added under, with the `yara_meta` types it was given there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreePath {
    pub path: String,
    #[serde(default)]
    pub yara_meta: Vec<String>,
}

/// One result of the tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeResult {
    /// The observable it's about, by index.
    pub observable: usize,
    /// The module, or the named instance, that wrote it.
    pub module: String,
    pub analysis_type: String,
    /// Its own tags, as ace3's analysis tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// What it added, in order: ace3's `analysis.observables`.
    #[serde(default)]
    pub added: Vec<TreeAddition>,
}

/// An observable a result added, and the path it added a file under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeAddition {
    pub observable: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl TreeObservable {
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }

    pub fn has_directive(&self, directive: &str) -> bool {
        self.directives.iter().any(|d| d == directive)
    }

    pub fn is_pending(&self, module: &str) -> bool {
        self.pending.iter().any(|m| m == module)
    }

    pub fn reference(&self) -> ObservableRef {
        ObservableRef::new(self.kind, self.value.clone())
    }

    /// Whether the file was given `type=<value>` under `path`: ace3's `has_yara_meta("type", value)`
    /// on the observable for that path.
    pub fn has_yara_type(&self, path: &str, value: &str) -> bool {
        let wanted = format!("type={value}");
        self.paths
            .iter()
            .filter(|p| p.path == path)
            .any(|p| p.yara_meta.contains(&wanted))
    }
}

impl TreeView {
    /// The task's own observable.
    pub fn this(&self) -> &TreeObservable {
        &self.observables[self.this]
    }

    pub fn observable(&self, index: usize) -> &TreeObservable {
        &self.observables[index]
    }

    /// The results on the observable at `index`, in the order they landed: ace3's
    /// `observable.all_analysis`.
    pub fn results_on(&self, index: usize) -> impl Iterator<Item = &TreeResult> + '_ {
        self.results.iter().filter(move |r| r.observable == index)
    }

    /// The observable's result of `analysis_type`, if it has one: ace3's `get_analysis`.
    pub fn result_of(&self, index: usize, analysis_type: &str) -> Option<&TreeResult> {
        self.results_on(index)
            .find(|r| r.analysis_type == analysis_type)
    }

    /// The results that added the observable at `index`, in the order they landed.
    pub fn added_by(&self, index: usize) -> impl Iterator<Item = &TreeResult> + '_ {
        self.results
            .iter()
            .filter(move |r| r.added.iter().any(|a| a.observable == index))
    }

    /// The observables of `kind` in the root, in the order they were added: ace3's
    /// `get_observables_by_type`.
    pub fn of_kind(&self, kind: ObservableKind) -> impl Iterator<Item = usize> + '_ {
        (0..self.observables.len()).filter(move |&i| self.observables[i].kind == kind)
    }

    /// Whether the root has a result of `analysis_type`: ace3's `get_analysis_by_type`.
    pub fn has_result_of(&self, analysis_type: &str) -> bool {
        self.results
            .iter()
            .any(|r| r.analysis_type == analysis_type)
    }

    /// The results on each observable, by index, in the order they landed.
    fn results_by_observable(&self) -> Vec<Vec<usize>> {
        let mut on = vec![Vec::new(); self.observables.len()];
        for (i, result) in self.results.iter().enumerate() {
            if let Some(list) = on.get_mut(result.observable) {
                list.push(i);
            }
        }
        on
    }

    /// The results that added each observable, by index, in the order they landed.
    fn adders_by_observable(&self) -> Vec<Vec<usize>> {
        let mut by = vec![Vec::new(); self.observables.len()];
        for (i, result) in self.results.iter().enumerate() {
            for added in &result.added {
                if let Some(list) = by.get_mut(added.observable)
                    && list.last() != Some(&i)
                {
                    list.push(i);
                }
            }
        }
        by
    }

    /// Whether the observable at `index`, or anything below it, has `tag`, on an observable or a
    /// result: ace3's `recurse_tree` with `has_tag`. Each is looked at once.
    pub fn tree_has_tag(&self, index: usize, tag: &str) -> bool {
        let on = self.results_by_observable();
        let mut seen = vec![false; self.observables.len()];
        let mut stack = vec![index];
        while let Some(observable) = stack.pop() {
            if observable >= seen.len() || std::mem::replace(&mut seen[observable], true) {
                continue;
            }
            if self.observables[observable].has_tag(tag) {
                return true;
            }
            for &i in &on[observable] {
                let result = &self.results[i];
                if result.tags.iter().any(|t| t == tag) {
                    return true;
                }
                stack.extend(result.added.iter().map(|a| a.observable));
            }
        }
        false
    }

    /// ace3's `search_down`: from the observable at `index` up through the results that added it
    /// and the observables those results are on, depth first in the order the results landed, the
    /// first observable `found` accepts. The observable itself isn't a candidate, and each is looked
    /// at once.
    pub fn search_up(&self, index: usize, mut found: impl FnMut(usize) -> bool) -> Option<usize> {
        let adders = self.adders_by_observable();
        let mut seen = vec![false; self.observables.len()];
        *seen.get_mut(index)? = true;
        // each frame is an observable and how many of its adders have been followed
        let mut stack = vec![(index, 0usize)];
        while let Some((observable, next)) = stack.last_mut() {
            let Some(&result) = adders[*observable].get(*next) else {
                stack.pop();
                continue;
            };
            *next += 1;
            let holder = self.results[result].observable;
            if holder >= seen.len() || std::mem::replace(&mut seen[holder], true) {
                continue;
            }
            if found(holder) {
                return Some(holder);
            }
            stack.push((holder, 0));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observable(kind: ObservableKind, value: &str, tags: &[&str]) -> TreeObservable {
        TreeObservable {
            kind,
            value: value.to_owned(),
            tags: tags.iter().map(|t| (*t).to_owned()).collect(),
            directives: Vec::new(),
            detections: 0,
            paths: Vec::new(),
            size: None,
            pending: Vec::new(),
            download: None,
        }
    }

    fn result(observable: usize, module: &str, added: &[usize]) -> TreeResult {
        TreeResult {
            observable,
            module: module.to_owned(),
            analysis_type: format!("{module}_analysis"),
            tags: Vec::new(),
            added: added
                .iter()
                .map(|&observable| TreeAddition {
                    observable,
                    path: None,
                })
                .collect(),
        }
    }

    /// email (0) -> attachment (1) -> macro stream (2); email -> conversation (3)
    fn tree() -> TreeView {
        TreeView {
            alert_type: None,
            whitelisted: false,
            this: 1,
            observables: vec![
                observable(ObservableKind::File, "email", &[]),
                observable(ObservableKind::File, "doc", &[]),
                observable(ObservableKind::File, "stream", &["macro"]),
                observable(ObservableKind::EmailConversation, "a|b", &["new_sender"]),
            ],
            results: vec![
                result(0, "email_analyzer", &[1, 3]),
                result(1, "officeparser3", &[2]),
            ],
            truncated: false,
        }
    }

    #[test]
    fn a_tag_below_is_found_and_one_beside_is_not() {
        let tree = tree();
        assert!(tree.tree_has_tag(1, "macro"));
        assert!(tree.tree_has_tag(0, "new_sender"));
        assert!(!tree.tree_has_tag(1, "new_sender"));
    }

    #[test]
    fn searching_up_finds_the_nearest_holder_first() {
        let tree = tree();
        assert_eq!(tree.search_up(2, |i| i == 1 || i == 0), Some(1));
        assert_eq!(tree.search_up(2, |i| i == 0), Some(0));
        assert_eq!(tree.search_up(0, |_| true), None);
        assert_eq!(
            tree.of_kind(ObservableKind::EmailConversation)
                .collect::<Vec<_>>(),
            [3]
        );
    }

    #[test]
    fn a_cycle_ends_the_walks() {
        let mut tree = tree();
        tree.results.push(result(2, "archive", &[1]));
        assert!(!tree.tree_has_tag(1, "nothing"));
        assert_eq!(tree.search_up(1, |_| false), None);
    }

    #[test]
    fn tree_files_match_by_name_and_size() {
        let files = TreeFiles {
            names_containing: &[".unknown_text_html"],
            max_size: 10,
            tagged: None,
        };
        assert!(files.wants("email.rfc822.unknown_text_html_000", 10, &[]));
        assert!(!files.wants("email.rfc822.unknown_text_html_000", 11, &[]));
        assert!(!files.wants("a.unknown_text_html/other", 1, &[]));
        let tagged = TreeFiles {
            names_containing: &[],
            max_size: 10,
            tagged: Some("tls_keylog"),
        };
        assert!(tagged.wants("keys.txt", 10, &["tls_keylog".to_owned()]));
        assert!(!tagged.wants("keys.txt", 11, &["tls_keylog".to_owned()]));
        assert!(!tagged.wants("keys.txt", 1, &["other".to_owned()]));
    }
}
