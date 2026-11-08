//! A compiled ruleset as bytes, keyed by their hash, with a manifest of what went into it
//! (ace3 #1051: yara_scanner keeps no record of what it compiled).
//!
//! yara-x's serialization is deterministic: two builds of the same rule files give the same
//! bytes, in one process or two and from checkouts in different directories (tests/ruleset.rs
//! checks this). So the key is the sha256 of the bytes, and it changes exactly when the
//! compiled rules do.
//!
//! The manifest says where the rules came from. In a git checkout with no uncommitted changes
//! under the signature directory, that is the commit. A directory outside git, or one with
//! changes, has no commit, and is known by the hash of its sources, which every manifest
//! records. `build_commit` builds a commit of a repository as git holds it, whatever its working
//! tree has, which is what the core's ruleset builds use (PLAN.md 2.25).

use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::load::{self, FileOutcome, LoadError, LoadOptions, Namespace, Ruleset};

/// What a ruleset was built from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// The sha256 of the serialized ruleset.
    pub key: String,
    /// The commit of the git repository holding the signature directory, when nothing under
    /// the directory differs from it.
    pub commit: Option<String>,
    /// The sha256 of every rule file's namespace, path and bytes (see `sources_sha256`).
    pub sources_sha256: String,
    pub yara_x_version: String,
    /// The files whose rules are in the ruleset, with their rules.
    pub files: Vec<IncludedFile>,
    /// The files left out, with why.
    pub left_out: Vec<LeftOutFile>,
    /// The rules in QA mode (`modifiers` holds `qa`), in file order, enabled or not, which 5.6's
    /// `yara_qa` router lists whether or not they have matched. A manifest written before this
    /// field existed reads it as empty.
    #[serde(default)]
    pub qa_rules: Vec<QaRule>,
}

/// A rule in QA mode, with the meta that says what it is. Every field but `path` is text the
/// rule's author wrote, so it's data to show, never markup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QaRule {
    pub namespace: String,
    /// The rule's file, relative to the signature directory.
    pub path: String,
    pub name: String,
    /// Its `uuid` meta, trimmed; None when it has none, and then its matches aren't kept.
    pub uuid: Option<String>,
    /// Its `enabled` meta. A disabled rule matches nothing that's kept.
    pub enabled: bool,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncludedFile {
    pub namespace: String,
    /// Relative to the signature directory.
    pub path: String,
    pub rules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeftOutFile {
    pub namespace: String,
    /// Relative to the signature directory.
    pub path: String,
    pub error: String,
}

/// A built ruleset: its bytes, its manifest, and the ruleset itself for scanning.
pub struct Built {
    pub bytes: Vec<u8>,
    pub manifest: Manifest,
    pub ruleset: Ruleset,
}

#[derive(Debug)]
pub enum BuildError {
    Load(LoadError),
    Serialize(String),
    /// git couldn't read the repository, or the commit isn't in it.
    Git(String),
    Io(std::io::Error),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::Load(e) => write!(f, "{e}"),
            BuildError::Serialize(e) => write!(f, "unable to serialize the ruleset: {e}"),
            BuildError::Git(e) => write!(f, "git: {e}"),
            BuildError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Compiles a signature directory and serializes the result.
pub fn build(signature_dir: &Path, options: &LoadOptions) -> Result<Built, BuildError> {
    build_with(signature_dir, options, git_commit(signature_dir))
}

/// Compiles the signature directory `dir` (relative to the repository's top) of the git
/// repository `repo` as it is at `commit`, and serializes the result. The files come from git's
/// objects into a temporary directory, so the working tree's state doesn't matter and nothing in
/// the repository changes. Only regular files are read; symbolic links and submodules aren't.
pub fn build_commit(
    repo: &Path,
    commit: &str,
    dir: &Path,
    options: &LoadOptions,
) -> Result<Built, BuildError> {
    let export = tempfile::Builder::new()
        .prefix("ace4-ruleset-")
        .tempdir()
        .map_err(BuildError::Io)?;
    let mut args = ["ls-tree", "-r", "-z", "--full-tree", commit]
        .map(OsStr::new)
        .to_vec();
    if !top_relative(dir).as_os_str().is_empty() {
        args.extend([OsStr::new("--"), top_relative(dir).as_os_str()]);
    }
    let listing = git_bytes(repo, &args)?;
    for entry in listing.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        let entry = String::from_utf8_lossy(entry);
        // <mode> SP <type> SP <object> TAB <path>
        let Some((header, path)) = entry.split_once('\t') else {
            return Err(BuildError::Git(format!(
                "unexpected ls-tree entry {entry:?}"
            )));
        };
        let mut fields = header.split(' ');
        let (Some(mode), Some(kind), Some(object)) = (fields.next(), fields.next(), fields.next())
        else {
            return Err(BuildError::Git(format!(
                "unexpected ls-tree entry {entry:?}"
            )));
        };
        if kind != "blob" || !matches!(mode, "100644" | "100755") {
            continue;
        }
        let Ok(relative) = Path::new(path).strip_prefix(top_relative(dir)) else {
            continue;
        };
        let bytes = git_bytes(
            repo,
            &[
                OsStr::new("cat-file"),
                OsStr::new("blob"),
                OsStr::new(object),
            ],
        )?;
        let target = export.path().join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(BuildError::Io)?;
        }
        std::fs::write(&target, bytes).map_err(BuildError::Io)?;
    }
    build_with(export.path(), options, Some(commit.to_owned()))
}

/// The commit `rev` names in the repository, such as `HEAD` or `main`.
pub fn resolve_commit(repo: &Path, rev: &str) -> Result<String, BuildError> {
    let spec = format!("{rev}^{{commit}}");
    let out = git_bytes(
        repo,
        &[
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new(&spec),
        ],
    )?;
    Ok(String::from_utf8_lossy(&out).trim().to_owned())
}

/// The id of the tree git holds at `dir` in `commit`, or None when the commit has no such
/// directory. Two commits with the same tree there build the same ruleset.
pub fn tree_id(repo: &Path, commit: &str, dir: &Path) -> Result<Option<String>, BuildError> {
    let spec = format!("{commit}:{}", top_relative(dir).to_string_lossy());
    match git_bytes(
        repo,
        &[
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("--quiet"),
            OsStr::new(&spec),
        ],
    ) {
        Ok(out) => Ok(Some(String::from_utf8_lossy(&out).trim().to_owned())),
        Err(BuildError::Git(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// `dir` as git names a path from the repository's top: the top itself is empty.
fn top_relative(dir: &Path) -> &Path {
    if dir == Path::new(".") {
        Path::new("")
    } else {
        dir
    }
}

fn build_with(
    signature_dir: &Path,
    options: &LoadOptions,
    commit: Option<String>,
) -> Result<Built, BuildError> {
    let namespaces = load::discover(signature_dir).map_err(|error| {
        BuildError::Load(LoadError::Discover {
            dir: signature_dir.to_path_buf(),
            error,
        })
    })?;
    let loaded = load::compile(&namespaces, options).map_err(BuildError::Load)?;
    let bytes = loaded
        .ruleset
        .rules
        .serialize()
        .map_err(|e| BuildError::Serialize(e.to_string()))?;

    let relative = |path: &Path| {
        path.strip_prefix(signature_dir)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/")
    };
    let mut files = Vec::new();
    let mut left_out = Vec::new();
    let mut qa_rules = Vec::new();
    for report in &loaded.files {
        match &report.outcome {
            FileOutcome::Included { rules } => {
                let path = relative(&report.path);
                qa_rules.extend(rules.iter().filter(|r| r.meta.is_qa()).map(|r| QaRule {
                    namespace: r.namespace.clone(),
                    path: path.clone(),
                    name: r.name.clone(),
                    uuid: r.meta.uuid().filter(|uuid| !uuid.is_empty()),
                    enabled: r.meta.enabled(),
                    tags: r.tags.clone(),
                }));
                files.push(IncludedFile {
                    namespace: report.namespace.clone(),
                    path,
                    rules: rules.iter().map(|r| r.name.clone()).collect(),
                });
            }
            FileOutcome::LeftOut { error } => left_out.push(LeftOutFile {
                namespace: report.namespace.clone(),
                path: relative(&report.path),
                error: error.clone(),
            }),
        }
    }

    let manifest = Manifest {
        key: key(&bytes),
        commit,
        sources_sha256: sources_sha256(signature_dir, &namespaces),
        yara_x_version: crate::YARA_X_VERSION.to_string(),
        files,
        left_out,
        qa_rules,
    };
    Ok(Built {
        bytes,
        manifest,
        ruleset: loaded.ruleset,
    })
}

impl Ruleset {
    /// Loads a ruleset that `build` serialized, and compiles each rule's filter again.
    ///
    /// The bytes must come from `build`: yara-x warns that rules from an untrusted source can
    /// make a scan panic. A build with yara-x's `rules-profiling` feature can't load a ruleset
    /// built without it, or the other way round.
    pub fn from_bytes(bytes: &[u8], options: &LoadOptions) -> Result<Ruleset, String> {
        let rules = yara_x::Rules::deserialize(bytes).map_err(|e| e.to_string())?;
        Ruleset::new(rules, options)
    }
}

/// A serialized ruleset's key: the sha256 of its bytes.
pub fn key(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The sha256 over every rule file, in the order `discover` lists them: for each, its
/// namespace, its path relative to the signature directory, its length and its bytes. A file
/// that can't be read counts with no bytes and a length of `u64::MAX`.
fn sources_sha256(signature_dir: &Path, namespaces: &[Namespace]) -> String {
    let mut hasher = Sha256::new();
    for namespace in namespaces {
        for path in &namespace.files {
            let relative = path.strip_prefix(signature_dir).unwrap_or(path);
            hasher.update(namespace.name.as_bytes());
            hasher.update([0]);
            hasher.update(relative.to_string_lossy().as_bytes());
            hasher.update([0]);
            match std::fs::read(path) {
                Ok(bytes) => {
                    hasher.update((bytes.len() as u64).to_le_bytes());
                    hasher.update(&bytes);
                }
                Err(_) => hasher.update(u64::MAX.to_le_bytes()),
            }
        }
    }
    hex(&hasher.finalize())
}

/// HEAD of the git repository holding `dir`, if nothing under `dir` differs from it,
/// untracked files included. `None` outside git, when git isn't installed, or when git
/// refuses the repository.
///
/// git runs with fsmonitor off, so a repository's own config can't make `git status` run a
/// program.
fn git_commit(dir: &Path) -> Option<String> {
    let head = git(dir, &["rev-parse", "--verify", "HEAD"])?;
    let changes = git(
        dir,
        &["status", "--porcelain", "--untracked-files=all", "--", "."],
    )?;
    if !changes.is_empty() {
        tracing::info!(
            dir = %dir.display(),
            "the signature directory differs from commit {head}, so the ruleset records no commit"
        );
        return None;
    }
    Some(head)
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    let out = git_bytes(dir, &args).ok()?;
    Some(String::from_utf8_lossy(&out).trim().to_string())
}

/// Runs git in `dir` with fsmonitor off and returns its stdout, or its stderr as the error.
///
/// Every repository is a safe directory here: the core reads a signatures checkout that another
/// user owns, such as one bind-mounted into its container, and git refuses a repository owned by
/// someone else unless told otherwise. The calls only read, and fsmonitor, the one setting that
/// would run a program the repository names, is off.
fn git_bytes(dir: &Path, args: &[&OsStr]) -> Result<Vec<u8>, BuildError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "core.fsmonitor=false", "-c", "safe.directory=*"])
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| BuildError::Git(format!("unable to run git: {e}")))?;
    if !output.status.success() {
        return Err(BuildError::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    Ok(output.stdout)
}
