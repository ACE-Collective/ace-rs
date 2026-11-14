//! A rule repository for SVS validation's tests (PLAN.md 7.10 batch 3): a bare origin and a working clone
//! that commits and pushes to it, as ace3's `tests/saq/svs/yara/conftest.py` makes one, and the source of
//! one rule, as its `rule()` writes it.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A rule repository: a bare origin, and a working clone that commits and pushes to it, as ace3's
/// `RuleRepo`.
pub struct RuleRepo {
    pub origin: PathBuf,
    pub work: PathBuf,
}

pub fn git_in(cwd: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .env("GIT_AUTHOR_NAME", "unittest")
        .env("GIT_AUTHOR_EMAIL", "unittest@localhost")
        .env("GIT_COMMITTER_NAME", "unittest")
        .env("GIT_COMMITTER_EMAIL", "unittest@localhost")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("runs git");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

impl RuleRepo {
    pub fn new(root: &Path) -> RuleRepo {
        let origin = root.join("origin");
        let work = root.join("work");
        std::fs::create_dir_all(&origin).expect("makes origin");
        std::fs::create_dir_all(&work).expect("makes work");
        git_in(&origin, &["init", "--bare", "--quiet", "-b", "main"]);
        git_in(&work, &["init", "--quiet", "-b", "main"]);
        git_in(
            &work,
            &["remote", "add", "origin", origin.to_str().unwrap()],
        );
        RuleRepo { origin, work }
    }

    /// Writes (or, for None, deletes) the files, adds the symbolic links, commits on `branch` and
    /// pushes. Returns the commit's id.
    pub fn commit_with(
        &self,
        files: &[(&str, Option<&[u8]>)],
        branch: &str,
        symlinks: &[(&str, &str)],
    ) -> String {
        let current = git_in(&self.work, &["symbolic-ref", "--short", "HEAD"]);
        if current.trim() != branch {
            let exists = !git_in(&self.work, &["branch", "--list", branch])
                .trim()
                .is_empty();
            if exists {
                git_in(&self.work, &["checkout", "--quiet", branch]);
            } else {
                git_in(&self.work, &["checkout", "--quiet", "-b", branch]);
            }
        }
        for (path, content) in files {
            let full = self.work.join(path);
            match content {
                None => std::fs::remove_file(&full).expect("removes"),
                Some(bytes) => {
                    std::fs::create_dir_all(full.parent().unwrap()).expect("makes it");
                    std::fs::write(&full, bytes).expect("writes");
                }
            }
        }
        for (path, target) in symlinks {
            let full = self.work.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).expect("makes it");
            std::os::unix::fs::symlink(target, &full).expect("links");
        }
        git_in(&self.work, &["add", "-A"]);
        git_in(
            &self.work,
            &["commit", "--quiet", "--allow-empty", "-m", "change"],
        );
        git_in(
            &self.work,
            &["push", "--quiet", "--force", "origin", branch],
        );
        git_in(&self.work, &["rev-parse", "HEAD"]).trim().to_owned()
    }

    pub fn commit(&self, files: &[(&str, &str)], branch: &str) -> String {
        let files: Vec<(&str, Option<&[u8]>)> = files
            .iter()
            .map(|(p, c)| (*p, Some(c.as_bytes())))
            .collect();
        self.commit_with(&files, branch, &[])
    }
}

/// The source of one rule, as ace3's test `rule()` writes it: its uuid meta when it has one, then each
/// meta, its strings and its condition.
pub fn rule(
    name: &str,
    uuid: Option<&str>,
    strings: &str,
    condition: &str,
    meta: &[(&str, &str)],
) -> String {
    let mut lines: Vec<String> = uuid
        .map(|u| format!("        uuid = \"{u}\""))
        .into_iter()
        .collect();
    for (key, value) in meta {
        lines.push(format!("        {key} = {value}"));
    }
    let meta = if lines.is_empty() {
        String::new()
    } else {
        format!("    meta:\n{}\n", lines.join("\n"))
    };
    format!(
        "rule {name} {{\n{meta}    strings:\n        {strings}\n    condition:\n        {condition}\n}}\n"
    )
}
