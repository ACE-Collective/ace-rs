//! SVS's own clone of a rule repository, and exporting a commit's rules from it: ace3's
//! `saq/svs/yara/repository.py`.
//!
//! Each repository in `svs.yara.repositories` gets a bare mirror under the mirror directory, fetched from
//! its URL. It is never the checkout the ruleset build reads (`ACE4_SIGNATURES_REPO`), so a validation can
//! neither change what production scans nor see a working tree someone edited by hand, and fetching only
//! reads the repository it fetches from.
//!
//! A commit is exported as the ruleset build reads it (`ace_yara::ruleset::build_commit`): from git's
//! objects, listed with `git ls-tree` and read with `git cat-file`, regular files only. A symbolic link or a
//! submodule is never written, and nor is a path with an empty, `.` or `..` part; each is recorded rather
//! than failing the export. The commit's whole tree counts against the caps, in members (files and
//! directories) and bytes, before anything is written, since a pull request controls what it contains. What
//! is written is every regular file under the signature directory, which is all the build compiles, and the
//! rule files elsewhere, so the report can say they aren't loaded.
//!
//! What differs from ace3's: ace3 exports with `git archive` and unpacks with tarfile's `data` filter, which
//! honours the commit's `.gitattributes` (`export-ignore`, `export-subst`) and keeps a symbolic link that
//! stays inside the tree. ace4's ruleset build does neither, so the export doesn't either. ace3 fetches with
//! its `git_repo_*` section's SSH key; here git runs with `ace serve`'s environment, so a site gives a key
//! through `GIT_SSH_COMMAND` or a credential in the URL, which no error shows.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// How long a local git command (`rev-parse`, `ls-tree`, `remote`) may take.
const LOCAL_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
/// How much of a failed git command's stderr goes into the error.
const STDERR_TAIL: usize = 4096;

/// A git operation on the mirror failed. The message never holds the repository's URL.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct RepositoryError(pub String);

/// What an export wrote, and what it didn't.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportResult {
    /// The commit's files and directories.
    pub members: u64,
    /// The bytes of its files.
    pub bytes: u64,
    /// `(path, reason)` of every entry that wasn't written.
    pub skipped: Vec<(String, String)>,
}

/// Whether `value` looks like a commit id: 7 to 64 hex digits. Anything else never reaches git, so a
/// request can't pass it an option or a revision expression.
pub fn is_valid_sha(value: &str) -> bool {
    (7..=64).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// SVS's mirror of one repository.
#[derive(Debug, Clone)]
pub struct Mirror {
    pub name: String,
    url: String,
    pub path: PathBuf,
    fetch_timeout: Duration,
}

/// The mirror held for one fetch and export; dropping it lets go.
pub struct MirrorLock {
    _file: std::fs::File,
}

impl Mirror {
    pub fn new(name: &str, url: &str, mirror_root: &Path, fetch_timeout: Duration) -> Mirror {
        Mirror {
            name: name.to_owned(),
            url: url.to_owned(),
            path: mirror_root.join(name),
            fetch_timeout,
        }
    }

    fn redact(&self, text: &str) -> String {
        if self.url.is_empty() {
            text.to_owned()
        } else {
            text.replace(&self.url, "<url>")
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new("git");
        command
            .arg("-C")
            .arg(&self.path)
            .args(["-c", "core.fsmonitor=false", "-c", "safe.directory=*"])
            // never a prompt for credentials, which would hang until the timeout
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "true")
            .stdin(Stdio::null())
            .process_group(0);
        command
    }

    fn git(
        &self,
        args: &[&str],
        timeout: Duration,
        error: &str,
    ) -> Result<Vec<u8>, RepositoryError> {
        let mut command = self.command();
        command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = command
            .spawn()
            .map_err(|e| RepositoryError(format!("{error}: unable to run git: {e}")))?;
        let (status, stdout, stderr) = wait(child, timeout).map_err(|e| match e {
            Waited::TimedOut => RepositoryError(format!(
                "{error}: git {} timed out after {} seconds",
                args[0],
                timeout.as_secs()
            )),
            Waited::Io(e) => RepositoryError(format!("{error}: {e}")),
        })?;
        if !status.success() {
            let stderr = String::from_utf8_lossy(&stderr);
            let stderr = stderr.trim();
            let tail =
                &stderr[stderr.floor_char_boundary(stderr.len().saturating_sub(STDERR_TAIL))..];
            return Err(RepositoryError(format!("{error}: {}", self.redact(tail))));
        }
        Ok(stdout)
    }

    /// Holds the mirror for one fetch and export: two validations of one repository must not fetch into it
    /// at once. Blocks until it has it.
    pub fn lock(&self) -> Result<MirrorLock, RepositoryError> {
        let parent = self.path.parent().unwrap_or(Path::new("/"));
        std::fs::create_dir_all(parent).map_err(|e| {
            RepositoryError(format!(
                "unable to make the mirror directory {}: {e}",
                parent.display()
            ))
        })?;
        let mut lock = self.path.clone().into_os_string();
        lock.push(".lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&lock)
            .map_err(|e| RepositoryError(format!("unable to open the mirror's lock: {e}")))?;
        // SAFETY: flock on a descriptor this function owns.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(RepositoryError(format!(
                "unable to lock the mirror: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(MirrorLock { _file: file })
    }

    /// Makes the mirror if it doesn't exist, points it at the URL and fetches `branches`, then each of
    /// `optional` on its own: one the remote doesn't have (a pull request's branch deleted on merge, or one
    /// only a fork has) is logged and skipped, and its commits are fetched by id instead
    /// (`fetch_commit`).
    pub fn ensure(&self, branches: &[&str], optional: &[&str]) -> Result<(), RepositoryError> {
        if !self.path.join("objects").is_dir() {
            std::fs::create_dir_all(&self.path)
                .map_err(|e| RepositoryError(format!("unable to make the mirror: {e}")))?;
            self.git(
                &["init", "--bare", "--quiet"],
                LOCAL_COMMAND_TIMEOUT,
                "unable to make the mirror",
            )?;
        }
        let remotes = self.git(
            &["remote"],
            LOCAL_COMMAND_TIMEOUT,
            "unable to read the mirror's remotes",
        )?;
        let has_origin = String::from_utf8_lossy(&remotes)
            .split_whitespace()
            .any(|r| r == "origin");
        let verb = if has_origin { "set-url" } else { "add" };
        self.git(
            &["remote", verb, "origin", &self.url],
            LOCAL_COMMAND_TIMEOUT,
            "unable to set the mirror's remote",
        )?;

        let branches: Vec<&str> = unique(branches.iter().copied().filter(|b| !b.is_empty()));
        let refspecs: Vec<String> = branches
            .iter()
            .map(|b| format!("+refs/heads/{b}:refs/heads/{b}"))
            .collect();
        let mut args = vec!["fetch", "--quiet", "--no-tags", "origin"];
        args.extend(refspecs.iter().map(String::as_str));
        self.git(
            &args,
            self.fetch_timeout,
            &format!(
                "unable to fetch {} of repository {}",
                branches.join(", "),
                self.name
            ),
        )?;

        for branch in unique(optional.iter().copied()) {
            if branch.is_empty() || branches.contains(&branch) {
                continue;
            }
            let refspec = format!("+refs/heads/{branch}:refs/heads/{branch}");
            if let Err(e) = self.git(
                &["fetch", "--quiet", "--no-tags", "origin", &refspec],
                self.fetch_timeout,
                &format!("unable to fetch {branch} of repository {}", self.name),
            ) {
                tracing::info!("{e}; its commits are fetched by id");
            }
        }
        Ok(())
    }

    /// Fetches one commit by id, for a commit no fetched branch has any more. Most servers allow it for a
    /// reachable commit.
    pub fn fetch_commit(&self, sha: &str) -> Result<(), RepositoryError> {
        if !is_valid_sha(sha) {
            return Err(RepositoryError(format!("{sha:?} is not a commit id")));
        }
        self.git(
            &["fetch", "--quiet", "--no-tags", "origin", sha],
            self.fetch_timeout,
            &format!("unable to fetch commit {sha} of repository {}", self.name),
        )
        .map(|_| ())
    }

    /// The full id of the commit `sha` names, or None when the mirror doesn't have it.
    pub fn resolve(&self, sha: &str) -> Result<Option<String>, RepositoryError> {
        if !is_valid_sha(sha) {
            return Err(RepositoryError(format!("{sha:?} is not a commit id")));
        }
        let spec = format!("{sha}^{{commit}}");
        Ok(self
            .git(
                &["rev-parse", "--verify", "--quiet", &spec],
                LOCAL_COMMAND_TIMEOUT,
                "commit not found",
            )
            .ok()
            .map(|out| String::from_utf8_lossy(&out).trim().to_owned())
            .filter(|id| !id.is_empty()))
    }

    /// Writes the rules of `sha` (a full id from `resolve`) into `dest`, which must exist: every regular
    /// file under `signature_dir`, and every rule file elsewhere (the module's docs).
    pub fn export(
        &self,
        sha: &str,
        dest: &Path,
        signature_dir: &str,
        max_bytes: Option<u64>,
        max_members: Option<u64>,
        timeout: Duration,
    ) -> Result<ExportResult, RepositoryError> {
        if !is_valid_sha(sha) {
            return Err(RepositoryError(format!("{sha:?} is not a commit id")));
        }
        let deadline = Instant::now() + timeout;
        let failed = |e: String| RepositoryError(format!("unable to export commit {sha}: {e}"));
        let listing = self.git(
            &["ls-tree", "-r", "-t", "-l", "-z", "--full-tree", sha],
            timeout,
            &format!("unable to export commit {sha}"),
        )?;

        let mut result = ExportResult::default();
        let mut wanted: Vec<(String, String)> = Vec::new();
        let prefix = if signature_dir.is_empty() {
            String::new()
        } else {
            format!("{signature_dir}/")
        };
        for entry in listing.split(|b| *b == 0).filter(|e| !e.is_empty()) {
            let entry = String::from_utf8_lossy(entry);
            // <mode> SP <type> SP <object> SP+ <size> TAB <path>
            let Some((header, path)) = entry.split_once('\t') else {
                return Err(failed(format!("unexpected ls-tree entry {entry:?}")));
            };
            let fields: Vec<&str> = header.split_whitespace().collect();
            let [mode, kind, object, size] = fields[..] else {
                return Err(failed(format!("unexpected ls-tree entry {entry:?}")));
            };
            result.members += 1;
            if let Some(max) = max_members
                && result.members > max
            {
                return Err(RepositoryError(format!(
                    "the commit has more than {max} files and directories (svs.yara.max_archive_members)"
                )));
            }
            if kind == "blob" {
                result.bytes += size.parse::<u64>().unwrap_or(0);
                if let Some(max) = max_bytes
                    && result.bytes > max
                {
                    return Err(RepositoryError(format!(
                        "the commit is larger than {max} bytes (svs.yara.max_archive_bytes)"
                    )));
                }
            }
            if kind == "tree" {
                continue;
            }
            let name = path.rsplit('/').next().unwrap_or(path);
            let in_signature_dir = path.starts_with(&prefix);
            if !in_signature_dir && !super::layout::is_rule_file(name) {
                continue;
            }
            if !is_safe_tree_path(path) {
                result
                    .skipped
                    .push((path.to_owned(), "the path leaves the tree".to_owned()));
                continue;
            }
            match (mode, kind) {
                ("100644" | "100755", "blob") => wanted.push((object.to_owned(), path.to_owned())),
                ("120000", _) => result.skipped.push((
                    path.to_owned(),
                    "a symbolic link: the ruleset build reads only regular files".to_owned(),
                )),
                ("160000", _) => result.skipped.push((
                    path.to_owned(),
                    "a submodule: the ruleset build reads only regular files".to_owned(),
                )),
                _ => result
                    .skipped
                    .push((path.to_owned(), format!("not a regular file (mode {mode})"))),
            }
        }

        self.write_blobs(&wanted, dest, deadline)
            .map_err(|e| match e {
                Waited::TimedOut => RepositoryError(format!(
                    "exporting commit {sha} timed out after {} seconds",
                    timeout.as_secs()
                )),
                Waited::Io(e) => failed(self.redact(&e.to_string())),
            })?;
        Ok(result)
    }

    /// Reads each `(object, path)` with one `git cat-file --batch` and writes it at `dest/path`.
    fn write_blobs(
        &self,
        wanted: &[(String, String)],
        dest: &Path,
        deadline: Instant,
    ) -> Result<(), Waited> {
        if wanted.is_empty() {
            return Ok(());
        }
        let mut command = self.command();
        command
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(Waited::Io)?;
        let pid = child.id();
        let done = Arc::new(AtomicBool::new(false));
        let timed_out = Arc::new(AtomicBool::new(false));
        let watchdog = {
            let (done, timed_out) = (done.clone(), timed_out.clone());
            std::thread::spawn(move || {
                while !done.load(Ordering::Acquire) {
                    if Instant::now() >= deadline {
                        timed_out.store(true, Ordering::Release);
                        kill_group(pid);
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            })
        };
        let mut stdin = child.stdin.take().expect("stdin is piped");
        let objects: Vec<String> = wanted.iter().map(|(o, _)| o.clone()).collect();
        let writer = std::thread::spawn(move || {
            for object in objects {
                if writeln!(stdin, "{object}").is_err() {
                    return;
                }
            }
        });
        let outcome = read_blobs(child.stdout.take().expect("stdout is piped"), wanted, dest);
        done.store(true, Ordering::Release);
        if outcome.is_err() {
            kill_group(pid);
        }
        let joined = writer.join().is_ok() & watchdog.join().is_ok();
        if let Err(e) = child.wait() {
            tracing::debug!("waiting for git cat-file: {e}");
        }
        if !joined {
            return Err(Waited::Io(std::io::Error::other(
                "a helper thread panicked",
            )));
        }
        if timed_out.load(Ordering::Acquire) {
            return Err(Waited::TimedOut);
        }
        outcome.map_err(Waited::Io)
    }
}

fn read_blobs(
    stdout: std::process::ChildStdout,
    wanted: &[(String, String)],
    dest: &Path,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stdout);
    let mut header = String::new();
    for (object, path) in wanted {
        header.clear();
        reader.read_line(&mut header)?;
        // <object> SP <type> SP <size> LF, then the content and LF
        let mut fields = header.split_whitespace();
        let (Some(id), Some("blob"), Some(size)) = (fields.next(), fields.next(), fields.next())
        else {
            return Err(std::io::Error::other(format!(
                "git cat-file answered {:?} for {object}",
                header.trim()
            )));
        };
        if id != object {
            return Err(std::io::Error::other(format!(
                "git cat-file answered {id} for {object}"
            )));
        }
        let size: u64 = size
            .parse()
            .map_err(|_| std::io::Error::other("git cat-file gave no size"))?;
        let target = dest.join(path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::File::create(&target)?;
        let copied = std::io::copy(&mut (&mut reader).take(size), &mut file)?;
        if copied != size {
            return Err(std::io::Error::other(format!("{path} was cut short")));
        }
        let mut newline = [0u8; 1];
        reader.read_exact(&mut newline)?;
    }
    Ok(())
}

/// A path git lists that stays inside the tree: no empty, `.` or `..` part, and not absolute.
fn is_safe_tree_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn unique<'a>(items: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let mut seen = BTreeSet::new();
    items.filter(|item| seen.insert(*item)).collect()
}

pub(crate) enum Waited {
    TimedOut,
    Io(std::io::Error),
}

/// Kills the process group `pid` leads: git and what it started, such as ssh.
pub(crate) fn kill_group(pid: u32) {
    if let Ok(pid) = i32::try_from(pid) {
        // SAFETY: a signal to a process group this process made.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}

/// Waits for `child` (made with its own process group) for at most `timeout`, reading its stdout and
/// stderr, and kills its group at the timeout.
pub(crate) fn wait(
    mut child: Child,
    timeout: Duration,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), Waited> {
    let deadline = Instant::now() + timeout;
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(stdout) = stdout.as_mut() {
            stdout.read_to_end(&mut bytes).ok();
        }
        bytes
    });
    let err = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(stderr) = stderr.as_mut() {
            stderr.read_to_end(&mut bytes).ok();
        }
        bytes
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                kill_group(child.id());
                child.wait().ok();
                out.join().ok();
                err.join().ok();
                return Err(Waited::TimedOut);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => {
                kill_group(child.id());
                return Err(Waited::Io(e));
            }
        }
    };
    let stdout = out.join().unwrap_or_default();
    let stderr = err.join().unwrap_or_default();
    Ok((status, stdout, stderr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::rule_repo::{RuleRepo, git_in};

    fn mirror(repo: &RuleRepo, root: &Path, url: Option<&str>) -> Mirror {
        Mirror::new(
            "rules",
            url.unwrap_or(repo.origin.to_str().unwrap()),
            &root.join("mirrors"),
            Duration::from_secs(60),
        )
    }

    fn export(mirror: &Mirror, sha: &str, dest: &Path) -> Result<ExportResult, RepositoryError> {
        export_capped(mirror, sha, dest, Some(1 << 20), Some(100))
    }

    fn export_capped(
        mirror: &Mirror,
        sha: &str,
        dest: &Path,
        max_bytes: Option<u64>,
        max_members: Option<u64>,
    ) -> Result<ExportResult, RepositoryError> {
        std::fs::create_dir_all(dest).expect("makes it");
        mirror.export(
            sha,
            dest,
            "yara",
            max_bytes,
            max_members,
            Duration::from_secs(60),
        )
    }

    /// test_repository.py's `test_is_valid_sha`.
    #[test]
    fn valid_shas() {
        assert!(is_valid_sha(&"a".repeat(40)));
        assert!(is_valid_sha("ABCDEF1"));
        assert!(!is_valid_sha("main"));
        assert!(!is_valid_sha("--upload-pack=x"));
        assert!(!is_valid_sha(""));
    }

    /// test_repository.py's `test_fetch_resolve_and_export`.
    #[test]
    fn fetch_resolve_and_export() {
        let tmp = tempfile::tempdir().expect("a directory");
        let repo = RuleRepo::new(&tmp.path().join("repo"));
        let base = repo.commit(
            &[("yara/acme/a.yar", "rule a { condition: false }\n")],
            "main",
        );
        let head = repo.commit(
            &[("yara/acme/b.yar", "rule b { condition: false }\n")],
            "feature",
        );

        let mirror = mirror(&repo, tmp.path(), None);
        {
            let _lock = mirror.lock().expect("locks");
            mirror.ensure(&["feature", "main"], &[]).expect("fetches");
        }
        assert_eq!(
            mirror.resolve(&base).unwrap().as_deref(),
            Some(base.as_str())
        );
        assert_eq!(
            mirror.resolve(&head[..12]).unwrap().as_deref(),
            Some(head.as_str())
        );
        assert_eq!(mirror.resolve(&"0".repeat(40)).unwrap(), None);

        let result = export(&mirror, &base, &tmp.path().join("base")).expect("exports");
        assert!(tmp.path().join("base/yara/acme/a.yar").exists());
        assert!(!tmp.path().join("base/yara/acme/b.yar").exists());
        assert!(result.skipped.is_empty());
        export(&mirror, &head, &tmp.path().join("head")).expect("exports");
        assert!(tmp.path().join("head/yara/acme/b.yar").exists());

        // a second ensure updates the mirror
        let newer = repo.commit(
            &[("yara/acme/c.yar", "rule c { condition: false }\n")],
            "feature",
        );
        mirror.ensure(&["feature", "main"], &[]).expect("fetches");
        assert_eq!(
            mirror.resolve(&newer).unwrap().as_deref(),
            Some(newer.as_str())
        );
    }

    /// test_repository.py's `test_a_commit_no_branch_contains_is_fetched_by_id`.
    #[test]
    fn a_commit_no_branch_contains_is_fetched_by_id() {
        let tmp = tempfile::tempdir().expect("a directory");
        let repo = RuleRepo::new(&tmp.path().join("repo"));
        repo.commit(&[("a.yar", "rule a { condition: false }\n")], "main");
        let orphaned = repo.commit(&[("b.yar", "rule b { condition: false }\n")], "gone");
        git_in(
            &repo.work,
            &["push", "--quiet", "origin", "--delete", "gone"],
        );
        git_in(
            &repo.origin,
            &["config", "uploadpack.allowAnySHA1InWant", "true"],
        );

        let mirror = mirror(&repo, tmp.path(), None);
        mirror.ensure(&["main"], &[]).expect("fetches");
        assert_eq!(mirror.resolve(&orphaned).unwrap(), None);
        mirror.fetch_commit(&orphaned).expect("fetches it by id");
        assert_eq!(
            mirror.resolve(&orphaned).unwrap().as_deref(),
            Some(orphaned.as_str())
        );
    }

    /// test_repository.py's `test_an_optional_branch_missing_from_the_remote_is_skipped`.
    #[test]
    fn an_optional_branch_missing_from_the_remote_is_skipped() {
        let tmp = tempfile::tempdir().expect("a directory");
        let repo = RuleRepo::new(&tmp.path().join("repo"));
        let merged = repo.commit(&[("a.yar", "rule a { condition: false }\n")], "main");
        let feature = repo.commit(&[("b.yar", "rule b { condition: false }\n")], "feature");

        let mirror = mirror(&repo, tmp.path(), None);
        mirror
            .ensure(&["main"], &["merged-and-deleted", "feature"])
            .expect("skips the missing branch");
        assert_eq!(
            mirror.resolve(&merged).unwrap().as_deref(),
            Some(merged.as_str())
        );
        assert_eq!(
            mirror.resolve(&feature).unwrap().as_deref(),
            Some(feature.as_str())
        );
        // the target branch itself is required
        assert!(mirror.ensure(&["no-such-target"], &[]).is_err());
    }

    /// test_repository.py's `test_an_escaping_symlink_is_skipped_and_recorded`. ace4's ruleset build reads
    /// only regular files, so a link that stays inside the tree isn't written either.
    #[test]
    fn a_symlink_is_skipped_and_recorded() {
        let tmp = tempfile::tempdir().expect("a directory");
        let repo = RuleRepo::new(&tmp.path().join("repo"));
        let sha = repo.commit_with(
            &[("yara/acme/a.yar", Some(b"rule a { condition: false }\n"))],
            "main",
            &[
                ("yara/acme/passwd.yar", "/etc/passwd"),
                ("yara/acme/up.yar", "../../../../outside.yar"),
                ("yara/acme/inside.yar", "a.yar"),
            ],
        );
        let mirror = mirror(&repo, tmp.path(), None);
        mirror.ensure(&["main"], &[]).expect("fetches");
        let tree = tmp.path().join("tree");
        let result = export(&mirror, &sha, &tree).expect("exports");

        let mut skipped: Vec<&str> = result.skipped.iter().map(|(p, _)| p.as_str()).collect();
        skipped.sort();
        assert_eq!(
            skipped,
            [
                "yara/acme/inside.yar",
                "yara/acme/passwd.yar",
                "yara/acme/up.yar"
            ]
        );
        assert!(
            result
                .skipped
                .iter()
                .all(|(_, why)| why.contains("symbolic link"))
        );
        assert!(!tree.join("yara/acme/passwd.yar").exists());
        assert!(std::fs::symlink_metadata(tree.join("yara/acme/inside.yar")).is_err());
        assert!(tree.join("yara/acme/a.yar").is_file());
    }

    /// test_repository.py's `test_the_export_is_capped`.
    #[test]
    fn the_export_is_capped() {
        let tmp = tempfile::tempdir().expect("a directory");
        let repo = RuleRepo::new(&tmp.path().join("repo"));
        let names: Vec<String> = (0..10).map(|i| format!("yara/acme/{i}.yar")).collect();
        let content = "x".repeat(1000);
        let files: Vec<(&str, &str)> = names
            .iter()
            .map(|n| (n.as_str(), content.as_str()))
            .collect();
        let sha = repo.commit(&files, "main");
        let mirror = mirror(&repo, tmp.path(), None);
        mirror.ensure(&["main"], &[]).expect("fetches");

        let error = export_capped(
            &mirror,
            &sha,
            &tmp.path().join("bytes"),
            Some(5000),
            Some(100),
        )
        .expect_err("too many bytes");
        assert!(error.0.contains("max_archive_bytes"), "{error}");
        let error = export_capped(
            &mirror,
            &sha,
            &tmp.path().join("members"),
            Some(1 << 20),
            Some(5),
        )
        .expect_err("too many members");
        assert!(error.0.contains("max_archive_members"), "{error}");
        export_capped(
            &mirror,
            &sha,
            &tmp.path().join("fits"),
            Some(10000),
            Some(20),
        )
        .expect("fits");

        // no limit when unset
        let result = export_capped(&mirror, &sha, &tmp.path().join("uncapped"), None, None)
            .expect("exports");
        assert_eq!(result.bytes, 10000);
        assert_eq!(
            std::fs::read_dir(tmp.path().join("uncapped/yara/acme"))
                .unwrap()
                .count(),
            10
        );
    }

    /// test_repository.py's `test_a_failing_fetch_does_not_show_the_url`.
    #[test]
    fn a_failing_fetch_does_not_show_the_url() {
        let tmp = tempfile::tempdir().expect("a directory");
        let repo = RuleRepo::new(&tmp.path().join("repo"));
        // git hides the user and password of a URL in its errors, but not a token in its path
        let secret = "https://127.0.0.1:1/s3cret-token/rules.git";
        let mirror = mirror(&repo, tmp.path(), Some(secret));
        let error = mirror.ensure(&["main"], &[]).expect_err("can't fetch");
        assert!(!error.0.contains("s3cret"), "{error}");
        assert!(error.0.contains("<url>"), "{error}");
    }

    /// test_repository.py's `test_an_unknown_commit_is_refused_before_git_sees_it`.
    #[test]
    fn an_unknown_commit_is_refused_before_git_sees_it() {
        let tmp = tempfile::tempdir().expect("a directory");
        let repo = RuleRepo::new(&tmp.path().join("repo"));
        let mirror = mirror(&repo, tmp.path(), None);
        let error = mirror.resolve("HEAD~1").expect_err("refused");
        assert!(error.0.contains("not a commit id"));
    }
}
