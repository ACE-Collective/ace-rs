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
//! records.

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
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::Load(e) => write!(f, "{e}"),
            BuildError::Serialize(e) => write!(f, "unable to serialize the ruleset: {e}"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Compiles a signature directory and serializes the result.
pub fn build(signature_dir: &Path, options: &LoadOptions) -> Result<Built, BuildError> {
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
    for report in &loaded.files {
        match &report.outcome {
            FileOutcome::Included { rules } => files.push(IncludedFile {
                namespace: report.namespace.clone(),
                path: relative(&report.path),
                rules: rules.iter().map(|r| r.name.clone()).collect(),
            }),
            FileOutcome::LeftOut { error } => left_out.push(LeftOutFile {
                namespace: report.namespace.clone(),
                path: relative(&report.path),
                error: error.clone(),
            }),
        }
    }

    let manifest = Manifest {
        key: key(&bytes),
        commit: git_commit(signature_dir),
        sources_sha256: sources_sha256(signature_dir, &namespaces),
        yara_x_version: yara_x::VERSION.to_string(),
        files,
        left_out,
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
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "core.fsmonitor=false"])
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
