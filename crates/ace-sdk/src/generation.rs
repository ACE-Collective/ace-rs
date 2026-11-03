//! Generations of a file a pool keeps on disk for a module, such as the YARA pool's rulesets
//! (PLAN.md 2.26), as the yara service's generations in ace3.
//!
//! A directory holds one subdirectory per generation, each with the file (`data`) and what it
//! is (`generation.json`), and a symbolic link, `current`, to the generation modules should
//! load. The pool publishes a new generation only once the file is complete and has loaded, and
//! then swaps the link with one rename, so a module reading `current` gets the old generation or
//! the new one, never part of either. A module reads the link once and both files through what
//! it named. The generation before the current one stays, for a process that read the link just
//! before the swap; older ones go.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The link to the current generation.
pub const CURRENT: &str = "current";
/// A generation's file.
pub const DATA: &str = "data";
/// A generation's `GenerationInfo`.
pub const INFO: &str = "generation.json";

/// What a generation's file is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationInfo {
    /// The file's sha256, as the bucket names it.
    pub key: String,
    /// The commit the file was built from.
    pub commit: String,
}

impl GenerationInfo {
    /// The generation's directory name, `<key>-<commit>`. Both are checked to be letters and
    /// digits, so the name stays inside the directory.
    fn dir_name(&self) -> io::Result<String> {
        let plain = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric());
        if !plain(&self.key) || !plain(&self.commit) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("a generation of {:?} at {:?}", self.key, self.commit),
            ));
        }
        Ok(format!("{}-{}", self.key, self.commit))
    }
}

/// One generation on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generation {
    pub info: GenerationInfo,
    /// Its directory.
    pub dir: PathBuf,
}

impl Generation {
    /// The generation's file.
    pub fn data(&self) -> PathBuf {
        self.dir.join(DATA)
    }
}

/// The generation `current` names in `dir`, or None before the first is published.
pub fn current(dir: &Path) -> io::Result<Option<Generation>> {
    let name = match std::fs::read_link(dir.join(CURRENT)) {
        Ok(name) => name,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let generation = dir.join(name);
    let info = std::fs::read(generation.join(INFO))?;
    let info: GenerationInfo = serde_json::from_slice(&info).map_err(io::Error::other)?;
    Ok(Some(Generation {
        info,
        dir: generation,
    }))
}

/// Moves the file at `data`, which must be in `dir`'s filesystem, into a new generation, points
/// `current` at it, and removes every generation but it and the one before. Directories are
/// left readable by every user and files by every user, since task processes run as a user of
/// their own.
pub fn publish(dir: &Path, info: &GenerationInfo, data: &Path) -> io::Result<Generation> {
    use std::os::unix::fs::PermissionsExt;

    let name = info.dir_name()?;
    let previous = current(dir)?;
    let target = dir.join(&name);
    if previous.as_ref().is_some_and(|p| p.dir == target) {
        std::fs::remove_file(data)?;
        return Ok(Generation {
            info: info.clone(),
            dir: target,
        });
    }
    let staging = dir.join(format!(".staging-{name}"));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    std::fs::create_dir(&staging)?;
    std::fs::rename(data, staging.join(DATA))?;
    std::fs::write(
        staging.join(INFO),
        serde_json::to_vec(info).map_err(io::Error::other)?,
    )?;
    for (path, mode) in [
        (staging.join(DATA), 0o644),
        (staging.join(INFO), 0o644),
        (staging.clone(), 0o755),
    ] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    if target.exists() {
        std::fs::remove_dir_all(&target)?;
    }
    std::fs::rename(&staging, &target)?;

    let link = dir.join(format!(".current-{name}"));
    if link.symlink_metadata().is_ok() {
        std::fs::remove_file(&link)?;
    }
    std::os::unix::fs::symlink(&name, &link)?;
    std::fs::rename(&link, dir.join(CURRENT))?;

    let keep = previous.map(|p| p.dir);
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let hidden = path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with('.'));
        if path == target || Some(&path) == keep.as_ref() || hidden || !path.is_dir() {
            continue;
        }
        if path.symlink_metadata()?.file_type().is_symlink() {
            continue;
        }
        std::fs::remove_dir_all(&path)?;
    }
    Ok(Generation {
        info: info.clone(),
        dir: target,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(key: &str) -> GenerationInfo {
        GenerationInfo {
            key: key.to_owned(),
            commit: "c0ffee".to_owned(),
        }
    }

    #[test]
    fn publishing_swaps_current_and_keeps_one_generation_before_it() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(current(dir.path()).unwrap(), None);
        for (n, key) in ["aa", "bb", "cc"].iter().enumerate() {
            let download = dir.path().join(".download");
            std::fs::write(&download, format!("generation {n}")).unwrap();
            let published = publish(dir.path(), &info(key), &download).unwrap();
            let now = current(dir.path()).unwrap().unwrap();
            assert_eq!(now, published);
            assert_eq!(
                std::fs::read_to_string(now.data()).unwrap(),
                format!("generation {n}")
            );
        }
        let mut names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["bb-c0ffee", "cc-c0ffee", "current"]);
        assert!(publish(dir.path(), &info("../x"), &dir.path().join("none")).is_err());
    }
}
