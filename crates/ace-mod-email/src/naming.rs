//! Names for the files a module writes, as ace3's file manager picks them
//! (`saq/analysis/file_manager/local_file_manager.py`): a name from inside a hostile file is
//! cleaned so it stays inside the alert, and a name already taken gets a `_NNN` suffix.
//!
//! ace3 checks what is already in the alert's directory. A module here sees only its own
//! result, so a name counts as taken when the input file or an earlier output of the same
//! result has it.

use std::collections::{BTreeMap, BTreeSet};

use sha1::Digest;

/// ace3's `NAME_MAX_BYTES`.
const NAME_MAX_BYTES: usize = 255;
/// Room kept in a name for a `_NNN` suffix.
const UNIQUE_SUFFIX_BYTES: usize = 8;
/// A longer "extension" is part of the name.
const MAX_EXTENSION_BYTES: usize = 32;
const MAX_RELATIVE_PATH_BYTES: usize = 1024;

/// `os.path.splitext` of one path component: leading dots belong to the stem.
pub fn splitext(name: &str) -> (&str, &str) {
    let leading = name.len() - name.trim_start_matches('.').len();
    match name[leading..].rfind('.') {
        Some(dot) => name.split_at(leading + dot),
        None => (name, ""),
    }
}

/// `shorten_basename_for_suffix`: `basename + suffix`, cut so it fits `max_bytes` of UTF-8, with
/// eight hex digits of the basename's sha1 before the suffix when it had to be cut.
pub fn shorten_basename_for_suffix(basename: &str, suffix: &str, max_bytes: usize) -> String {
    let combined = format!("{basename}{suffix}");
    if combined.len() <= max_bytes {
        return combined;
    }
    let digest = sha1::Sha1::digest(basename.as_bytes());
    let hex: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();
    let tail = format!(".{hex}{suffix}");
    let available = max_bytes.saturating_sub(tail.len());
    let mut end = available.min(basename.len());
    while !basename.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{tail}", &basename[..end])
}

/// `clean_file_name`: each `/`-separated part a plain file name.
pub fn clean_file_name(name: &str) -> String {
    let mut components: Vec<String> = Vec::new();
    for component in name.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        let component = if component == ".." { "_" } else { component };
        let component = component.replace(['\\', '\0'], "_");
        let (mut stem, mut ext) = splitext(&component);
        if ext.len() > MAX_EXTENSION_BYTES {
            (stem, ext) = (&component, "");
        }
        components.push(shorten_basename_for_suffix(
            stem,
            ext,
            NAME_MAX_BYTES - UNIQUE_SUFFIX_BYTES,
        ));
    }
    while components.len() > 1 && components.join("/").len() > MAX_RELATIVE_PATH_BYTES {
        components.remove(0);
    }
    if components.is_empty() {
        return "_".to_owned();
    }
    let mut path = components.join("/");
    // a drive letter is ordinary on Linux, but a path inside an alert can't start with one
    if path.as_bytes().get(1) == Some(&b':') && path.as_bytes()[0].is_ascii_alphabetic() {
        path.replace_range(1..2, "_");
    }
    path
}

/// The names one result has used.
#[derive(Debug, Default)]
pub struct OutputNames {
    taken: BTreeSet<String>,
    /// base path -> the `_NNN` index to try next
    next_suffix: BTreeMap<String, usize>,
}

impl OutputNames {
    /// Names for a result about the file at `input`, whose own name is taken.
    pub fn new(input: &str) -> Self {
        OutputNames {
            taken: BTreeSet::from([input.to_owned()]),
            next_suffix: BTreeMap::new(),
        }
    }

    pub fn is_taken(&self, path: &str) -> bool {
        self.taken.contains(path)
    }

    /// Marks a path the result uses as is, such as the headers file.
    pub fn take(&mut self, path: &str) {
        self.taken.insert(path.to_owned());
    }

    /// `create_output_file`: the cleaned name, or the first free `<name>_NNN<ext>` beside it.
    pub fn output_file(&mut self, name: &str) -> String {
        let base = clean_file_name(name);
        let path = match self.next_suffix.get(&base).copied() {
            None if !self.taken.contains(&base) => base,
            start => {
                let (dir, file) = match base.rsplit_once('/') {
                    Some((dir, file)) => (Some(dir), file),
                    None => (None, base.as_str()),
                };
                let (stem, ext) = splitext(file);
                let mut index = start.unwrap_or(0);
                let candidate = loop {
                    let name = format!("{stem}_{index:03}{ext}");
                    let candidate = match dir {
                        Some(dir) => format!("{dir}/{name}"),
                        None => name,
                    };
                    if !self.taken.contains(&candidate) {
                        break candidate;
                    }
                    index += 1;
                };
                self.next_suffix.insert(base.clone(), index + 1);
                candidate
            }
        };
        self.taken.insert(path.clone());
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitext_like_python() {
        assert_eq!(splitext("a.b.c"), ("a.b", ".c"));
        assert_eq!(splitext(".bashrc"), (".bashrc", ""));
        assert_eq!(splitext("..a.b"), ("..a", ".b"));
        assert_eq!(splitext("noext"), ("noext", ""));
    }

    #[test]
    fn names_are_cleaned() {
        assert_eq!(clean_file_name("../../etc/passwd"), "_/_/etc/passwd");
        assert_eq!(clean_file_name("/abs//x/./y"), "abs/x/y");
        assert_eq!(clean_file_name("a\\b"), "a_b");
        assert_eq!(clean_file_name(""), "_");
        assert_eq!(clean_file_name("C:evil.exe"), "C_evil.exe");
        let long = format!("{}.txt", "a".repeat(300));
        let cleaned = clean_file_name(&long);
        assert!(cleaned.len() <= 247, "{}", cleaned.len());
        assert!(cleaned.ends_with(".txt"));
    }

    #[test]
    fn taken_names_get_suffixes() {
        let mut names = OutputNames::new("email.rfc822");
        assert_eq!(names.output_file("email.rfc822"), "email_000.rfc822");
        assert_eq!(
            names.output_file("email.rfc822.email.rfc822"),
            "email.rfc822.email.rfc822"
        );
        assert_eq!(
            names.output_file("email.rfc822.email.rfc822"),
            "email.rfc822.email_000.rfc822"
        );
        assert_eq!(
            names.output_file("email.rfc822.email.rfc822"),
            "email.rfc822.email_001.rfc822"
        );
        assert_eq!(names.output_file("dir/x.txt"), "dir/x.txt");
        assert_eq!(names.output_file("dir/x.txt"), "dir/x_000.txt");
    }
}
