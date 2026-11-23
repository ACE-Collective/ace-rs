//! Loading every hunt of a type from its rule directories: what ace3's `HuntManager` does in
//! `load_hunts_from_config` and `_list_hunt_yaml` (`saq/collectors/hunter/manager.py`).
//!
//! A rule directory's hunts are its `.yaml` files, not its subdirectories', leaving out
//! `template.yaml` and `*.include.yaml`. Each loads on its own, so one that fails fails alone
//! with its error, as ace3 logs it and carries on. A hunt whose `type` isn't the manager's fails,
//! and so does one whose name another hunt of the type already has. ace3 lists a directory in
//! `os.scandir` order, which is the filesystem's, so which of two hunts with one name fails can
//! change between hosts; ace-rs lists by name.
//!
//! Running hunts, watching their files for changes and reloading are 6.4's and 6.7's: each
//! [`Hunt`] says which files it was read from, and each failure which file failed.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::HuntError;
use crate::loader::{Hunt, LoadOptions, load_hunt};
use crate::types::HuntType;
use crate::value::py_repr;

/// One hunt file and what loading it gave.
#[derive(Debug)]
pub struct LoadedHunt {
    pub path: PathBuf,
    pub result: Result<Hunt, HuntError>,
}

/// The hunt files in `rule_dirs`, in each directory by name. A rule directory that isn't one is
/// skipped, as ace3 logs it and skips it.
pub fn hunt_files(rule_dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in rule_dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            // DirEntry.is_file() in Python follows a symbolic link
            .filter(|e| e.path().is_file())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|name| {
                name.ends_with(".yaml")
                    && name != "template.yaml"
                    && !name.ends_with(".include.yaml")
            })
            .collect();
        names.sort();
        out.extend(names.into_iter().map(|name| join(dir, &name)));
    }
    out
}

/// `os.path.join(dir, name)`, keeping the directory as it was given.
fn join(dir: &Path, name: &str) -> PathBuf {
    PathBuf::from(crate::paths::join(&dir.to_string_lossy(), name))
}

/// Loads every hunt of `kind` in `rule_dirs`.
pub fn load_hunts(
    kind: &dyn HuntType,
    rule_dirs: &[PathBuf],
    options: &LoadOptions,
) -> Vec<LoadedHunt> {
    let mut names = BTreeSet::new();
    hunt_files(rule_dirs)
        .into_iter()
        .map(|path| {
            let result = load_hunt(&path, kind, options).and_then(|hunt| {
                // HuntManager.add_hunt
                if hunt.config.kind != kind.name() {
                    return Err(HuntError::python(
                        "ValueError",
                        format!(
                            "hunt Hunt({}[{}]) has wrong type for {}",
                            hunt.config.name,
                            hunt.config.kind,
                            kind.name()
                        ),
                    ));
                }
                if !names.insert(hunt.config.name.clone()) {
                    return Err(HuntError::python(
                        "KeyError",
                        py_repr(&format!("duplicate hunt {}", hunt.config.name)),
                    ));
                }
                Ok(hunt)
            });
            LoadedHunt { path, result }
        })
        .collect()
}
