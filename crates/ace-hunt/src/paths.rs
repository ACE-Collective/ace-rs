//! Paths as Python's `os.path` handles them on POSIX, as strings.
//!
//! ace3's loader keeps an include's path as `os.path.join` makes it, unnormalized, and remembers
//! which files it has read by that text, so ace4 does the same with the same functions.

use std::path::{Path, PathBuf};

pub fn isabs(path: &str) -> bool {
    path.starts_with('/')
}

/// `os.path.join(a, b)`.
pub fn join(a: &str, b: &str) -> String {
    if isabs(b) || a.is_empty() {
        b.to_owned()
    } else if a.ends_with('/') {
        format!("{a}{b}")
    } else {
        format!("{a}/{b}")
    }
}

/// `os.path.dirname(path)`.
pub fn dirname(path: &str) -> &str {
    let head = match path.rfind('/') {
        Some(i) => &path[..=i],
        None => "",
    };
    if !head.is_empty() && !head.chars().all(|c| c == '/') {
        head.trim_end_matches('/')
    } else {
        head
    }
}

/// `os.path.normpath(path)`.
pub fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let initial = if path.starts_with("//") && !path.starts_with("///") {
        "//"
    } else if path.starts_with('/') {
        "/"
    } else {
        ""
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if !initial.is_empty() && parts.is_empty() {
                    // `/..` is `/`
                } else if parts.last().is_some_and(|p| *p != "..") {
                    parts.pop();
                } else {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let joined = format!("{initial}{}", parts.join("/"));
    if joined.is_empty() {
        ".".to_owned()
    } else {
        joined
    }
}

/// `os.path.abspath(path)` with `cwd` as the working directory.
pub fn abspath(path: &str, cwd: &str) -> String {
    if isabs(path) {
        normpath(path)
    } else {
        normpath(&join(cwd, path))
    }
}

/// `os.path.realpath(path)`: symbolic links resolved for as much of the path as exists.
pub fn realpath(path: &str) -> PathBuf {
    let path = Path::new(path);
    if let Ok(real) = path.canonicalize() {
        return real;
    }
    let mut missing = Vec::new();
    let mut existing = path;
    while let Some(parent) = existing.parent() {
        if let Some(name) = existing.file_name() {
            missing.push(name.to_owned());
        }
        existing = parent;
        if let Ok(real) = existing.canonicalize() {
            let mut out = real;
            for name in missing.iter().rev() {
                out.push(name);
            }
            return PathBuf::from(normpath(&out.to_string_lossy()));
        }
    }
    PathBuf::from(normpath(&path.to_string_lossy()))
}

/// ace3's `_is_under`: whether `path`, symbolic links resolved, lies under `root`.
pub fn is_under(path: &str, root: &Path) -> bool {
    let root = realpath(&root.to_string_lossy());
    realpath(path).starts_with(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn these_match_python() {
        assert_eq!(join("/a/b", "c"), "/a/b/c");
        assert_eq!(join("/a/b/", "c"), "/a/b/c");
        assert_eq!(join("/a", "/c"), "/c");
        assert_eq!(dirname("/a/b/c.yaml"), "/a/b");
        assert_eq!(dirname("c.yaml"), "");
        assert_eq!(dirname("/c.yaml"), "/");
        assert_eq!(normpath("/a/b/../c/./d"), "/a/c/d");
        assert_eq!(normpath("/../a"), "/a");
        assert_eq!(normpath("a/../../b"), "../b");
        assert_eq!(normpath("//a//b"), "//a/b");
        assert_eq!(abspath("x/../y", "/w"), "/w/y");
    }
}
