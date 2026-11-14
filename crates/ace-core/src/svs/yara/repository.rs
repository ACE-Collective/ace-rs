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
//! stays inside the tree. ace4's ruleset build does neither, so the export doesn't either.
//!
//! **The SSH key.** ace3 fetches with its `git_repo_*` section's `ssh_key_path`, a file on the node, as
//! `GIT_SSH_COMMAND="ssh -i <path> -o IdentitiesOnly=yes -o StrictHostKeyChecking=no"` (`saq/git.py`). Here
//! a repository's `ssh_key` names a secret of the overlay's `secrets:` (`env:` or `file:`, PLAN.md 2.24),
//! whose value is the private key's text, and `ace serve` and `ace svs yara validate` resolve only the
//! names the repositories give. ssh takes a key only as a file, and refuses one others can read, which a
//! Compose secret in `/run/secrets` is. So each fetch writes the key to a file of its own, mode 0600 in a
//! directory of mode 0700 beside the mirror, gives git ace3's command with that path, and removes the
//! directory when git has ended, whatever happened; one a killed process left goes when the mirror is next
//! locked. Only `git fetch` gets it: no other command reaches the remote. The key is never logged:
//! `Secret`'s `Debug` hides it, and an error has git's stderr with the URL replaced and any line of the key
//! replaced too, though neither git nor ssh prints one. The host key is not checked, as in ace3
//! (`StrictHostKeyChecking=no`); `IdentitiesOnly=yes` keeps ssh to this key.
//! A repository with no `ssh_key` fetches with `ace serve`'s environment, as before, so a site may still
//! give `GIT_SSH_COMMAND` there or a credential in the URL, which no error shows. A repository whose
//! `ssh_key` names a secret that isn't set doesn't fetch at all (`ValidationConfig::ssh_key`).

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ace_sdk::Secret;
use serde::{Deserialize, Serialize};

/// The options ace3 gives ssh after the key (`saq/git.py`): only this key, and no host key check.
const SSH_OPTIONS: &str = "-o IdentitiesOnly=yes -o StrictHostKeyChecking=no";
/// The shortest line of a key an error replaces: shorter ones (`-----END`'s are longer) aren't secret.
const KEY_LINE_MIN: usize = 16;

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

/// One entry of a commit's tree, as `git ls-tree -l` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    /// `100644`, `100755`, `120000` (a symbolic link), `160000` (a submodule) or `040000` (a directory).
    pub mode: String,
    /// `blob`, `tree` or `commit`.
    pub kind: String,
    pub object: String,
    /// A blob's size; None for a directory or a submodule.
    pub size: Option<u64>,
    pub path: String,
}

impl TreeEntry {
    /// A regular file, the only kind anything of SVS reads.
    pub fn is_regular_file(&self) -> bool {
        self.kind == "blob" && matches!(self.mode.as_str(), "100644" | "100755")
    }
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
    /// The SSH private key a fetch gives git, if the repository has one.
    ssh_key: Option<Secret>,
    /// The ssh program of `GIT_SSH_COMMAND`, as a shell word: `ssh`, or a test's stand-in.
    ssh_program: String,
}

/// A fetch's copy of the SSH key: a file only this user reads, in a directory of its own that goes when
/// this is dropped.
struct KeyFile {
    dir: tempfile::TempDir,
}

impl KeyFile {
    /// Writes `key` beside the mirror. A private key's file ends with a newline, which a secret's value
    /// has lost.
    fn write(beside: &Path, mirror: &str, key: &Secret) -> std::io::Result<KeyFile> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        std::fs::create_dir_all(beside)?;
        let dir = tempfile::Builder::new()
            .prefix(&KeyFile::prefix(mirror))
            .tempdir_in(beside)?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.path().join("key"))?;
        let text = key.expose();
        file.write_all(text.as_bytes())?;
        if !text.ends_with('\n') {
            file.write_all(b"\n")?;
        }
        file.sync_all()?;
        Ok(KeyFile { dir })
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join("key")
    }

    /// What the directory of a key of the mirror named `mirror` starts with. A repository's name has no
    /// `@` and doesn't start with `.`, so it's no mirror's path and no other mirror's prefix.
    fn prefix(mirror: &str) -> String {
        format!(".ssh-key@{mirror}@")
    }

    /// Removes the key directories a killed process left for the mirror named `mirror`. Only the holder of
    /// the mirror's lock calls it: every fetch into a mirror runs under that lock, so none of them is in use.
    fn remove_left_over(beside: &Path, mirror: &str) {
        let prefix = KeyFile::prefix(mirror);
        let Ok(entries) = std::fs::read_dir(beside) else {
            return;
        };
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(&prefix)
                && let Err(e) = std::fs::remove_dir_all(entry.path())
            {
                tracing::warn!(
                    "unable to remove a left over ssh key directory of repository {mirror}: {e}"
                );
            }
        }
    }
}

/// `text` as one word of a shell command, as git runs `GIT_SSH_COMMAND` through a shell.
fn shell_word(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
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
            ssh_key: None,
            ssh_program: "ssh".to_owned(),
        }
    }

    /// The mirror fetching with this SSH private key (the module's docs), or with the process's
    /// environment for None.
    pub fn with_ssh_key(mut self, key: Option<Secret>) -> Mirror {
        self.ssh_key = key;
        self
    }

    fn redact(&self, text: &str) -> String {
        let mut text = if self.url.is_empty() {
            text.to_owned()
        } else {
            text.replace(&self.url, "<url>")
        };
        if let Some(key) = &self.ssh_key {
            for line in key.expose().lines().map(str::trim) {
                if line.len() >= KEY_LINE_MIN && !line.starts_with("-----") {
                    text = text.replace(line, "<key>");
                }
            }
        }
        text
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
        self.git_capped(args, timeout, error, None)
    }

    /// `git`, with at most `max_stdout` bytes of output: a command that prints more is killed and fails,
    /// so a listing of a repository of any size can't fill memory.
    fn git_capped(
        &self,
        args: &[&str],
        timeout: Duration,
        error: &str,
        max_stdout: Option<u64>,
    ) -> Result<Vec<u8>, RepositoryError> {
        let mut command = self.command();
        command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // only a fetch reaches the remote, so only a fetch has the key; its file goes when git has ended
        let _key_file = match &self.ssh_key {
            Some(key) if args.first() == Some(&"fetch") => {
                let beside = self.path.parent().unwrap_or(Path::new("/"));
                let file = KeyFile::write(beside, &self.name, key).map_err(|e| {
                    RepositoryError(format!("{error}: unable to write the ssh key's file: {e}"))
                })?;
                command.env(
                    "GIT_SSH_COMMAND",
                    format!(
                        "{} -i {} {SSH_OPTIONS}",
                        self.ssh_program,
                        shell_word(&file.path().to_string_lossy())
                    ),
                );
                Some(file)
            }
            _ => None,
        };
        let child = command
            .spawn()
            .map_err(|e| RepositoryError(format!("{error}: unable to run git: {e}")))?;
        let (status, stdout, stderr) =
            wait_capped(child, timeout, max_stdout).map_err(|e| match e {
                Waited::TimedOut => RepositoryError(format!(
                    "{error}: git {} timed out after {} seconds",
                    args[0],
                    timeout.as_secs()
                )),
                Waited::Io(e) => RepositoryError(format!("{error}: {e}")),
            })?;
        if let Some(max) = max_stdout
            && stdout.len() as u64 > max
        {
            return Err(RepositoryError(format!(
                "{error}: git {} printed more than {max} bytes",
                args[0]
            )));
        }
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
        KeyFile::remove_left_over(parent, &self.name);
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
        // --update-shallow: a remote that is itself a shallow clone gives its branch with the history it
        // has, where git otherwise refuses the ref
        let mut args = vec![
            "fetch",
            "--quiet",
            "--no-tags",
            "--update-shallow",
            "origin",
        ];
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
                &[
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--update-shallow",
                    "origin",
                    &refspec,
                ],
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

    /// The full id of the commit the mirror's `branch` is at, as the last `ensure` fetched it, or None when
    /// the mirror has no such branch.
    pub fn head(&self, branch: &str) -> Result<Option<String>, RepositoryError> {
        if branch.is_empty() || branch.starts_with('-') || branch.contains("..") {
            return Err(RepositoryError(format!("{branch:?} is not a branch name")));
        }
        let spec = format!("refs/heads/{branch}^{{commit}}");
        Ok(self
            .git(
                &["rev-parse", "--verify", "--quiet", &spec],
                LOCAL_COMMAND_TIMEOUT,
                "branch not found",
            )
            .ok()
            .map(|out| String::from_utf8_lossy(&out).trim().to_owned())
            .filter(|id| is_valid_sha(id)))
    }

    /// Every entry of `sha` (a full id) under the directory `dir`, files and directories, as git lists
    /// them: nothing is read or written. A listing longer than `max_listing_bytes` fails, so a commit of any
    /// size is refused before its entries are held.
    pub fn list_tree(
        &self,
        sha: &str,
        dir: &str,
        max_listing_bytes: u64,
        timeout: Duration,
    ) -> Result<Vec<TreeEntry>, RepositoryError> {
        if !is_valid_sha(sha) {
            return Err(RepositoryError(format!("{sha:?} is not a commit id")));
        }
        if !is_safe_tree_path(dir) {
            return Err(RepositoryError(format!(
                "{dir:?} is not a directory of a tree"
            )));
        }
        let error = format!("unable to list {dir} of commit {sha}");
        let listing = self.git_capped(
            &[
                "ls-tree",
                "-r",
                "-t",
                "-l",
                "-z",
                "--full-tree",
                sha,
                "--",
                dir,
            ],
            timeout,
            &error,
            Some(max_listing_bytes),
        )?;
        let mut entries = Vec::new();
        for entry in listing.split(|b| *b == 0).filter(|e| !e.is_empty()) {
            let entry = String::from_utf8_lossy(entry);
            // <mode> SP <type> SP <object> SP+ <size> TAB <path>
            let parsed = entry.split_once('\t').and_then(|(header, path)| {
                let fields: Vec<&str> = header.split_whitespace().collect();
                let [mode, kind, object, size] = fields[..] else {
                    return None;
                };
                Some(TreeEntry {
                    mode: mode.to_owned(),
                    kind: kind.to_owned(),
                    object: object.to_owned(),
                    size: size.parse().ok(),
                    path: path.to_owned(),
                })
            });
            match parsed {
                Some(entry) => entries.push(entry),
                None => {
                    return Err(RepositoryError(format!(
                        "{error}: unexpected ls-tree entry {entry:?}"
                    )));
                }
            }
        }
        Ok(entries)
    }

    /// The content of each blob in `objects`, in their order, read from git's objects with one
    /// `git cat-file --batch`: nothing is checked out or written. A blob larger than `max_each` fails the
    /// read; the caller takes each blob's size from `list_tree` and asks only for those it has room for.
    pub fn read_files(
        &self,
        objects: &[String],
        max_each: u64,
        timeout: Duration,
    ) -> Result<Vec<Vec<u8>>, RepositoryError> {
        let wanted: Vec<(String, String)> = objects
            .iter()
            .map(|object| (object.clone(), object.clone()))
            .collect();
        let mut contents = Vec::with_capacity(objects.len());
        self.cat_blobs(
            &wanted,
            Instant::now() + timeout,
            &mut |path, size, reader| {
                if size > max_each {
                    return Err(std::io::Error::other(format!(
                        "{path} is {size} bytes, more than {max_each}"
                    )));
                }
                let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
                let copied = reader.take(size).read_to_end(&mut bytes)?;
                if copied as u64 != size {
                    return Err(std::io::Error::other(format!("{path} was cut short")));
                }
                contents.push(bytes);
                Ok(())
            },
        )
        .map_err(|e| match e {
            Waited::TimedOut => RepositoryError(format!(
                "reading the files timed out after {} seconds",
                timeout.as_secs()
            )),
            Waited::Io(e) => RepositoryError(format!(
                "unable to read the files: {}",
                self.redact(&e.to_string())
            )),
        })?;
        Ok(contents)
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
        self.cat_blobs(wanted, deadline, &mut |path, size, reader| {
            let target = dest.join(path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut file = std::fs::File::create(&target)?;
            let copied = std::io::copy(&mut reader.take(size), &mut file)?;
            if copied != size {
                return Err(std::io::Error::other(format!("{path} was cut short")));
            }
            Ok(())
        })
    }

    /// Reads each `(object, path)` with one `git cat-file --batch`, giving `sink` its path, its size and
    /// a reader that holds exactly its content.
    fn cat_blobs(
        &self,
        wanted: &[(String, String)],
        deadline: Instant,
        sink: &mut BlobSink<'_>,
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
        let outcome = read_blobs(child.stdout.take().expect("stdout is piped"), wanted, sink);
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

/// What takes one blob: its path, its size, and a reader of its content.
type BlobSink<'a> = dyn FnMut(&str, u64, &mut dyn Read) -> std::io::Result<()> + 'a;

fn read_blobs(
    stdout: std::process::ChildStdout,
    wanted: &[(String, String)],
    sink: &mut BlobSink<'_>,
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
        let mut content = (&mut reader).take(size);
        sink(path, size, &mut content)?;
        // whatever the sink left unread, so the next header is where it should be
        std::io::copy(&mut content, &mut std::io::sink())?;
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
/// With `max_stdout`, it keeps at most that many bytes and one more of the child's stdout: a child that prints
/// more is killed, and the caller sees the extra byte and refuses the output.
pub(crate) fn wait_capped(
    mut child: Child,
    timeout: Duration,
    max_stdout: Option<u64>,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), Waited> {
    let deadline = Instant::now() + timeout;
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let pid = child.id();
    let out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(stdout) = stdout.as_mut() {
            match max_stdout {
                None => {
                    stdout.read_to_end(&mut bytes).ok();
                }
                Some(max) => {
                    stdout
                        .take(max.saturating_add(1))
                        .read_to_end(&mut bytes)
                        .ok();
                    if bytes.len() as u64 > max {
                        kill_group(pid);
                    }
                }
            }
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
    /// The catalog's reads (PLAN.md 7.10 batch 4): a branch's head, the entries under one directory, and
    /// blobs read into memory with nothing checked out. A listing or a blob over its cap fails, and a
    /// remote that is itself a shallow clone is fetched with the history it has.
    #[test]
    fn a_branch_is_listed_and_read_from_git_s_objects() {
        let tmp = tempfile::tempdir().expect("a directory");
        let repo = RuleRepo::new(&tmp.path().join("repo"));
        repo.commit(&[("atomics/T1003/T1003.yaml", "first\n")], "main");
        let head = repo.commit_with(
            &[
                (
                    "atomics/T1003/T1003.yaml",
                    Some(b"attack_technique: T1003\n"),
                ),
                ("atomics/T1003/src/helper.yaml", Some(b"helper\n")),
                ("atomics/big.bin", Some(&[0u8; 5000])),
                ("elsewhere/T1/T1.yaml", Some(b"not under atomics\n")),
            ],
            "main",
            &[("atomics/T1004/T1004.yaml", "../T1003/T1003.yaml")],
        );
        let mirror = mirror(&repo, &tmp.path().join("mirrors"), None);
        let _lock = mirror.lock().expect("locks");
        mirror.ensure(&["main"], &[]).expect("fetches");
        assert_eq!(mirror.head("main").expect("reads"), Some(head.clone()));
        assert_eq!(mirror.head("nowhere").expect("reads"), None);
        assert!(mirror.head("-x").is_err());

        let timeout = Duration::from_secs(60);
        let entries = mirror
            .list_tree(&head, "atomics", 1 << 20, timeout)
            .expect("lists");
        let shown: Vec<(&str, &str, Option<u64>)> = entries
            .iter()
            .map(|e| (e.path.as_str(), e.mode.as_str(), e.size))
            .collect();
        assert_eq!(
            shown,
            [
                ("atomics", "040000", None),
                ("atomics/T1003", "040000", None),
                ("atomics/T1003/T1003.yaml", "100644", Some(24)),
                ("atomics/T1003/src", "040000", None),
                ("atomics/T1003/src/helper.yaml", "100644", Some(7)),
                ("atomics/T1004", "040000", None),
                ("atomics/T1004/T1004.yaml", "120000", Some(19)),
                ("atomics/big.bin", "100644", Some(5000)),
            ]
        );
        assert!(entries[2].is_regular_file() && !entries[6].is_regular_file());
        // a listing over its cap is refused, as is a directory that leaves the tree
        let error = mirror
            .list_tree(&head, "atomics", 100, timeout)
            .expect_err("over the cap");
        assert!(error.0.contains("printed more than 100 bytes"), "{error}");
        assert!(mirror.list_tree(&head, "../x", 1 << 20, timeout).is_err());
        assert!(
            mirror
                .list_tree(&head, "-r", 1 << 20, timeout)
                .expect("no such directory")
                .is_empty()
        );

        let objects = vec![entries[4].object.clone(), entries[2].object.clone()];
        let contents = mirror.read_files(&objects, 100, timeout).expect("reads");
        assert_eq!(
            contents,
            [b"helper\n".to_vec(), b"attack_technique: T1003\n".to_vec()]
        );
        assert!(
            mirror
                .read_files(&[], 100, timeout)
                .expect("reads")
                .is_empty()
        );
        let error = mirror
            .read_files(&[entries[7].object.clone()], 100, timeout)
            .expect_err("over the cap");
        assert!(error.0.contains("5000 bytes, more than 100"), "{error}");
        // nothing was checked out: the mirror is bare
        assert!(!mirror.path.join("atomics").exists());

        // a remote that is a shallow clone: its one commit is the branch
        let shallow = tmp.path().join("shallow");
        git_in(
            tmp.path(),
            &[
                "clone",
                "--quiet",
                "--depth",
                "1",
                "--branch",
                "main",
                &format!("file://{}", repo.origin.display()),
                shallow.to_str().expect("a path"),
            ],
        );
        let from_shallow = Mirror::new(
            "shallow",
            shallow.to_str().expect("a path"),
            &tmp.path().join("mirrors"),
            timeout,
        );
        let _lock = from_shallow.lock().expect("locks");
        from_shallow
            .ensure(&["main"], &[])
            .expect("fetches a shallow remote");
        assert_eq!(from_shallow.head("main").expect("reads"), Some(head));
    }

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

    /// A stand-in for ssh, run as `sh <script>`: it writes its arguments, the key file `-i` names and that
    /// file's and its directory's modes under `record`, then runs the command git asked the remote for
    /// here, so the fetch reads the origin on this machine and nothing uses the network. With `fail`, it
    /// prints the key's file instead and exits 1, as no ssh does. git asks an ssh it doesn't know for
    /// `-G` first, to learn its options, and takes a failure as an ssh with none.
    fn stand_in_ssh(dir: &Path, fail: bool) -> (String, PathBuf) {
        let record = dir.join("ssh-record");
        std::fs::create_dir_all(&record).expect("makes it");
        let script = dir.join("stand-in-ssh.sh");
        let end = if fail {
            "cat \"$key\" >&2; exit 1"
        } else {
            "eval \"exec $last\""
        };
        std::fs::write(
            &script,
            format!(
                "for a in \"$@\"; do [ \"$a\" = -G ] && exit 1; done\n\
                 r={}\n\
                 printf '%s\\n' \"$@\" > \"$r/args\"\n\
                 env > \"$r/env\"\n\
                 key=\n\
                 while [ $# -gt 0 ]; do\n\
                   case \"$1\" in\n\
                     -i) key=\"$2\"; cp \"$2\" \"$r/key\"; stat -c %a \"$2\" > \"$r/mode\"; \
                         stat -c %a \"$(dirname \"$2\")\" > \"$r/dirmode\"; printf '%s' \"$2\" > \"$r/path\"; shift 2;;\n\
                     *) last=\"$1\"; shift;;\n\
                   esac\n\
                 done\n\
                 {end}\n",
                shell_word(record.to_str().unwrap())
            ),
        )
        .expect("writes the stand-in");
        (
            format!("sh {}", shell_word(script.to_str().unwrap())),
            record,
        )
    }

    const TEST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
        QyNTUxOQAAACBub3QgYSByZWFsIGtleSwgb25seSBhIHRlc3QgZml4dHVyZSEhISE=\n\
        -----END OPENSSH PRIVATE KEY-----";

    /// The repository's configured key is what git is given: ace3's `GitRepo.env`, which
    /// `SvsRepository._env` uses. The key reaches ssh as a file of its own that only this user reads, with
    /// ace3's options, for a fetch and for nothing else, and is gone afterwards.
    #[test]
    fn a_fetch_gives_git_the_configured_ssh_key() {
        let tmp = tempfile::tempdir().expect("a directory");
        // a mirror directory with a space and a quote in it: the command is a shell's
        let root = tmp.path().join("it's a root");
        let repo = RuleRepo::new(&tmp.path().join("repo"));
        let sha = repo.commit(
            &[("yara/acme/a.yar", "rule a { condition: true }\n")],
            "main",
        );
        let url = format!("ssh://git@rules.invalid{}", repo.origin.to_str().unwrap());
        let (program, record) = stand_in_ssh(tmp.path(), false);
        let mut mirror = Mirror::new(
            "rules",
            &url,
            &root.join("mirrors"),
            Duration::from_secs(60),
        )
        .with_ssh_key(Some(Secret::new(TEST_KEY)));
        mirror.ssh_program = program.clone();
        let _lock = mirror.lock().expect("locks");
        mirror.ensure(&["main"], &[]).expect("fetches through ssh");
        assert_eq!(mirror.resolve(&sha).unwrap().as_deref(), Some(sha.as_str()));

        let read = |name: &str| std::fs::read_to_string(record.join(name)).expect(name);
        // the key, whole, ending in the newline a key file has
        assert_eq!(read("key"), format!("{TEST_KEY}\n"));
        assert_eq!(read("mode").trim(), "600");
        assert_eq!(read("dirmode").trim(), "700");
        let args = read("args");
        let args: Vec<&str> = args.lines().collect();
        let key_path = read("path");
        assert_eq!(
            args[..6],
            [
                "-i",
                key_path.as_str(),
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=no"
            ],
            "ace3's command"
        );
        assert!(args.contains(&"git@rules.invalid"), "{args:?}");
        // beside the mirror, and gone once git ended
        assert!(
            Path::new(&key_path).starts_with(root.join("mirrors")),
            "{key_path}"
        );
        assert!(!Path::new(&key_path).exists());
        let left: Vec<String> = std::fs::read_dir(root.join("mirrors"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".ssh-key"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
        // the key is in no variable of git's or ssh's environment
        assert!(!read("env").contains("b3BlbnNzaC1rZXktdjE"));
        // and Debug hides it
        assert!(!format!("{mirror:?}").contains("b3BlbnNzaC1rZXktdjE"));

        // a command that doesn't reach the remote has no key: nothing is recorded again
        std::fs::remove_dir_all(&record).unwrap();
        std::fs::create_dir_all(&record).unwrap();
        mirror.resolve(&sha).unwrap();
        assert!(!record.join("args").exists());
        // fetching one commit by id is a fetch too: one the mirror doesn't have, so git asks the remote
        let side = repo.commit(
            &[("yara/acme/b.yar", "rule b { condition: true }\n")],
            "side",
        );
        mirror.fetch_commit(&side).expect("fetches by id");
        assert_eq!(
            mirror.resolve(&side).unwrap().as_deref(),
            Some(side.as_str())
        );
        assert_eq!(read("key"), format!("{TEST_KEY}\n"));

        // a mirror with no key leaves ssh to the environment: git isn't given this command
        std::fs::remove_dir_all(&record).unwrap();
        std::fs::create_dir_all(&record).unwrap();
        let mut plain = Mirror::new(
            "plain",
            &url,
            &root.join("mirrors"),
            Duration::from_secs(60),
        );
        plain.ssh_program = program;
        let mut command = plain.command();
        command.args(["fetch", "origin"]);
        assert!(
            !command
                .get_envs()
                .any(|(name, _)| name == "GIT_SSH_COMMAND")
        );
    }

    /// A fetch that fails never shows the key, even from an ssh that prints it, and its file still goes.
    /// A key directory a killed process left goes when the mirror is next locked.
    #[test]
    fn a_failing_fetch_does_not_show_the_ssh_key() {
        let tmp = tempfile::tempdir().expect("a directory");
        let repo = RuleRepo::new(&tmp.path().join("repo"));
        repo.commit(
            &[("yara/acme/a.yar", "rule a { condition: true }\n")],
            "main",
        );
        let url = format!("ssh://git@rules.invalid{}", repo.origin.to_str().unwrap());
        let (program, record) = stand_in_ssh(tmp.path(), true);
        let mirrors = tmp.path().join("mirrors");
        let mut mirror = Mirror::new("rules", &url, &mirrors, Duration::from_secs(60))
            .with_ssh_key(Some(Secret::new(TEST_KEY)));
        mirror.ssh_program = program;
        let error = mirror.ensure(&["main"], &[]).expect_err("ssh fails");
        assert!(error.0.contains("unable to fetch main"), "{error}");
        assert!(
            error.0.contains("<key>"),
            "the stand-in printed it: {error}"
        );
        for line in TEST_KEY.lines().filter(|line| !line.starts_with("-----")) {
            assert!(!error.0.contains(line.trim()), "{error}");
        }
        assert!(!error.0.contains("rules.invalid"), "{error}");
        let key_path = std::fs::read_to_string(record.join("path")).expect("ran");
        assert!(!Path::new(&key_path).exists());

        // what a killed fetch left: this mirror's goes at its next lock, another mirror's stays
        let left = mirrors.join(format!("{}left", KeyFile::prefix("rules")));
        let other = mirrors.join(format!("{}left", KeyFile::prefix("rules-2")));
        for dir in [&left, &other] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("key"), TEST_KEY).unwrap();
        }
        let _lock = mirror.lock().expect("locks");
        assert!(!left.exists());
        assert!(other.exists());
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
