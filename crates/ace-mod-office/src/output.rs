//! ace3's `create_output_file` (`saq/analysis/file_manager/local_file_manager.py`) for a module
//! that names files from inside a document: the name is cleaned so it stays in the alert, a
//! directory component taken by a file moves to the next free `_NNN` name, and a file name already
//! taken gets a `_NNN` suffix, searching on from where the last search for that name stopped.
//!
//! ace3 checks what is on its disk. A task sees only its own input and outputs, so those are what
//! is taken: the input file, the directories it sits in, and what the result made before.

use std::collections::{BTreeMap, BTreeSet};

use ace_mod_email::naming::{clean_file_name, splitext};

#[derive(Debug, Default)]
pub struct OutputFiles {
    files: BTreeSet<String>,
    dirs: BTreeSet<String>,
    next_suffix: BTreeMap<String, usize>,
    moved_dirs: BTreeMap<String, String>,
}

/// `os.path.splitext` of a path: the extension of its last component.
fn split_path_ext(path: &str) -> (&str, &str) {
    let start = path.rfind('/').map_or(0, |at| at + 1);
    let (_, ext) = splitext(&path[start..]);
    path.split_at(path.len() - ext.len())
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else {
        format!("{dir}/{name}")
    }
}

impl OutputFiles {
    /// What's taken for a module analyzing the file at `input`.
    pub fn new(input: &str) -> Self {
        let mut taken = OutputFiles::default();
        taken.files.insert(input.to_owned());
        let mut at = input;
        while let Some((parent, _)) = at.rsplit_once('/') {
            taken.dirs.insert(parent.to_owned());
            at = parent;
        }
        taken
    }

    fn exists(&self, path: &str) -> bool {
        self.files.contains(path) || self.dirs.contains(path)
    }

    /// `create_output_file(name)`: the path of a new, empty file.
    pub fn create(&mut self, name: &str) -> String {
        let relative = clean_file_name(name);
        let (dir, base) = match relative.rsplit_once('/') {
            Some((dir, base)) => (dir.to_owned(), base.to_owned()),
            None => (String::new(), relative.clone()),
        };
        let directory = self.output_directory(&dir);
        let base_path = join(&directory, &base);
        let target = self.free_path(&base_path);
        self.files.insert(target.clone());
        target
    }

    /// `_free_path`.
    fn free_path(&mut self, path: &str) -> String {
        let index = match self.next_suffix.get(path) {
            Some(index) => *index,
            None if !self.exists(path) => return path.to_owned(),
            None => 0,
        };
        let (stem, ext) = split_path_ext(path);
        let mut index = index;
        let candidate = loop {
            let candidate = format!("{stem}_{index:03}{ext}");
            if !self.exists(&candidate) {
                break candidate;
            }
            index += 1;
        };
        self.next_suffix.insert(path.to_owned(), index + 1);
        candidate
    }

    /// `_output_directory`.
    fn output_directory(&mut self, relative_dir: &str) -> String {
        let mut directory = String::new();
        if relative_dir.is_empty() {
            return directory;
        }
        for component in relative_dir.split('/') {
            let wanted = join(&directory, component);
            let mut path = self
                .moved_dirs
                .get(&wanted)
                .cloned()
                .unwrap_or(wanted.clone());
            let mut index = 0;
            loop {
                if self.dirs.contains(&path) {
                    break;
                }
                if !self.files.contains(&path) {
                    self.dirs.insert(path.clone());
                    break;
                }
                let (stem, ext) = split_path_ext(&wanted);
                path = format!("{stem}_{index:03}{ext}");
                index += 1;
                self.moved_dirs.insert(wanted.clone(), path.clone());
            }
            directory = path;
        }
        directory
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_cleaned_and_numbered_as_ace3_numbers_them() {
        let mut out = OutputFiles::new("names.xml");
        assert_eq!(out.create("names.xml.xml/_"), "names.xml.xml/_");
        // the directory `_` is a file now, so it moves
        assert_eq!(
            out.create("names.xml.xml/_/_/etc/escape.txt"),
            "names.xml.xml/__000/_/etc/escape.txt"
        );
        assert_eq!(
            out.create("names.xml.xml/same.bin"),
            "names.xml.xml/same.bin"
        );
        assert_eq!(
            out.create("names.xml.xml/same.bin"),
            "names.xml.xml/same_000.bin"
        );
        assert_eq!(
            out.create("names.xml.xml/same.bin"),
            "names.xml.xml/same_001.bin"
        );
        assert_eq!(out.create("names.xml"), "names_000.xml");
        assert_eq!(out.create("x/.hidden"), "x/.hidden");
        assert_eq!(out.create("x/.hidden"), "x/.hidden_000");
    }
}
