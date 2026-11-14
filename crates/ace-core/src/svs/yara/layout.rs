//! Which directories of a repository's commit the YARA pool loads as namespaces: ace3's
//! `saq/svs/yara/layout.py`.
//!
//! The ruleset build (PLAN.md 2.25, `ace_yara::ruleset::build_commit`) reads one directory of the
//! signatures repository, its signature directory: each directory directly inside it is a namespace, and the
//! `.yar` and `.yara` files directly inside a namespace (any case) are its rules. Files loose in the
//! signature directory and files nested deeper are not loaded. So a repository's layout is its signature
//! directory, relative to its top, and a namespace a change adds is validated with it.
//!
//! ace3 derives the layout from where `service_yara.signature_dir` sits against the checkout, and has a
//! second, *linked*, layout, where entries of the signature directory are symbolic links into the checkout.
//! ace4's ruleset build has only the first, so a repository names its signature directory
//! (`svs.yara.repositories`) and there's no linked layout to derive.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The extensions of a rule file, compared without case.
pub const YARA_FILE_EXTENSIONS: [&str; 2] = [".yar", ".yara"];

/// A repository SVS can validate: ace3's `RepoLayout` in its contained form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoLayout {
    pub repository: String,
    /// The signature directory relative to the repository's top, `/`-separated; empty for the top itself.
    pub signature_dir: String,
}

impl RepoLayout {
    pub fn new(repository: &str, signature_dir: &str) -> Self {
        let signature_dir = signature_dir
            .split('/')
            .filter(|part| !part.is_empty() && *part != ".")
            .collect::<Vec<_>>()
            .join("/");
        RepoLayout {
            repository: repository.to_owned(),
            signature_dir,
        }
    }
}

/// A rule file of the commit the YARA pool would not load, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotLoaded {
    /// Relative to the repository's top.
    pub path: String,
    pub reason: String,
}

/// One namespace of an exported commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeNamespace {
    pub name: String,
    /// Its directory in the export.
    pub directory: PathBuf,
    /// Its rule files, in name order.
    pub files: Vec<PathBuf>,
}

/// The namespaces of one exported commit, and the rule files in it the YARA pool would not load.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TreeLayout {
    pub namespaces: Vec<TreeNamespace>,
    pub not_loaded: Vec<NotLoaded>,
    /// Namespaces the layout names that the commit doesn't have. ace4's layout names none, so this is
    /// always empty; the report keeps ace3's field.
    pub absent: Vec<String>,
}

pub(crate) fn is_rule_file(name: &str) -> bool {
    let name = name.to_lowercase();
    YARA_FILE_EXTENSIONS.iter().any(|ext| name.ends_with(ext))
}

fn sorted_entries(dir: &Path) -> Vec<(String, PathBuf)> {
    let mut entries: Vec<(String, PathBuf)> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
                .collect()
        })
        .unwrap_or_default();
    entries.sort();
    entries
}

fn relative(path: &Path, root: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// The namespaces of the commit exported at `tree_root`, and every other rule file in it, with why the
/// YARA pool would not load it.
pub fn tree_layout(layout: &RepoLayout, tree_root: &Path) -> TreeLayout {
    let mut result = TreeLayout::default();
    let signature_dir = if layout.signature_dir.is_empty() {
        tree_root.to_path_buf()
    } else {
        tree_root.join(&layout.signature_dir)
    };
    if signature_dir.is_dir() {
        for (name, directory) in sorted_entries(&signature_dir) {
            if !directory.is_dir() {
                continue;
            }
            let files = sorted_entries(&directory)
                .into_iter()
                .filter(|(name, path)| is_rule_file(name) && path.is_file())
                .map(|(_, path)| path)
                .collect();
            result.namespaces.push(TreeNamespace {
                name,
                directory,
                files,
            });
        }
    }

    let loaded: Vec<&PathBuf> = result.namespaces.iter().flat_map(|n| &n.files).collect();
    let namespace_dirs: Vec<&PathBuf> = result.namespaces.iter().map(|n| &n.directory).collect();
    let mut stack = vec![tree_root.to_path_buf()];
    let mut found = Vec::new();
    while let Some(dir) = stack.pop() {
        for (name, path) in sorted_entries(&dir) {
            if path.is_dir() {
                stack.push(path);
            } else if is_rule_file(&name) && !loaded.contains(&&path) {
                found.push((dir.clone(), path));
            }
        }
    }
    found.sort_by(|a, b| a.1.cmp(&b.1));
    for (dir, path) in found {
        let reason = if namespace_dirs.contains(&&dir) {
            "not a regular file"
        } else if dir == signature_dir {
            "loose in the signature directory: only the files inside its directories are loaded"
        } else if namespace_dirs.iter().any(|n| dir.starts_with(n)) {
            "nested below a namespace directory: only the files directly inside it are loaded"
        } else {
            "not in a directory the YARA pool loads"
        };
        result.not_loaded.push(NotLoaded {
            path: relative(&path, tree_root),
            reason: reason.to_owned(),
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(path: &Path) {
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("makes the directory");
        std::fs::write(path, "rule x { condition: false }\n").expect("writes");
    }

    /// test_layout.py's `test_tree_layout_lists_namespaces_and_what_is_not_loaded`.
    #[test]
    fn tree_layout_lists_namespaces_and_what_is_not_loaded() {
        let tmp = tempfile::tempdir().expect("a directory");
        let tree = tmp.path().join("tree");
        touch(&tree.join("yara/acme/a.yar"));
        touch(&tree.join("yara/acme/B.YARA"));
        touch(&tree.join("yara/acme/notes.txt"));
        touch(&tree.join("yara/acme/deeper/c.yar"));
        touch(&tree.join("yara/loose.yar"));
        touch(&tree.join("docs/example.yar"));
        std::fs::create_dir_all(tree.join("yara/empty")).expect("makes it");

        let result = tree_layout(&RepoLayout::new("r", "yara"), &tree);

        let namespaces: Vec<(String, Vec<String>)> = result
            .namespaces
            .iter()
            .map(|n| {
                let files = n
                    .files
                    .iter()
                    .map(|f| f.file_name().unwrap().to_string_lossy().into_owned())
                    .collect();
                (n.name.clone(), files)
            })
            .collect();
        assert_eq!(
            namespaces,
            [
                (
                    "acme".to_owned(),
                    vec!["B.YARA".to_owned(), "a.yar".to_owned()]
                ),
                ("empty".to_owned(), vec![])
            ]
        );
        let mut not_loaded: Vec<(String, String)> = result
            .not_loaded
            .iter()
            .map(|n| {
                (
                    n.path.clone(),
                    n.reason.split(':').next().unwrap().to_owned(),
                )
            })
            .collect();
        not_loaded.sort();
        assert_eq!(
            not_loaded,
            [
                (
                    "docs/example.yar".to_owned(),
                    "not in a directory the YARA pool loads".to_owned()
                ),
                (
                    "yara/acme/deeper/c.yar".to_owned(),
                    "nested below a namespace directory".to_owned()
                ),
                (
                    "yara/loose.yar".to_owned(),
                    "loose in the signature directory".to_owned()
                ),
            ]
        );
        assert!(result.absent.is_empty());

        // the repository's top as the signature directory
        let top = tree_layout(&RepoLayout::new("r", ""), &tree.join("yara"));
        assert_eq!(top.namespaces.len(), 2);
        assert_eq!(top.not_loaded[0].path, "acme/deeper/c.yar");
    }
}
