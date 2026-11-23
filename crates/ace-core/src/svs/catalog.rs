//! The Atomic Red Team test catalog (PLAN.md 7.10 batch 4): ace3's `saq/svs/catalog.py`.
//!
//! ACE never runs a test. It holds Atomic Red Team repositories only as a catalog: to validate a run's test
//! GUID, to show a test's name, description and commands, to check its supported platforms, and to know its
//! ATT&CK technique.
//!
//! Each repository in the overlay's `svs.catalog.repositories` gets a bare mirror, SVS's own
//! (`super::yara::repository::Mirror`, with its per-repository SSH key), fetched from its URL. A refresh
//! fetches the repository's branch and, when its commit changed, reads `atomics/T*/T*.yaml` of that commit
//! from git's objects into `svs.catalog_tests`. A test without an `auto_generated_guid` is skipped with a
//! warning, and a GUID already taken by another test (in this repository or another) is skipped too: the
//! first one read keeps it. A test that disappears keeps its row, with `removed_at` set, so its runs keep
//! their test. So does every test of a repository taken out of `svs.catalog.repositories`: nothing reads
//! it any more, so its tests can't stay in the catalog.
//!
//! A refresh locks its repository's row while it writes, so two replicas never interleave.
//!
//! **Bounds.** A catalog repository is someone else's content, so what one refresh takes from it is held:
//! - git: the fetch and each read to `fetch_timeout_seconds`, with the process group killed at the timeout.
//! - the listing: `git ls-tree` of `atomics/` prints at most [`MAX_LISTING_BYTES`]; more fails the refresh
//!   before any entry is held.
//! - files: at most `max_files` atomic files, more fails the refresh; a file over `max_file_bytes` is
//!   skipped and counted, as ace3 skips one over 10 MiB; and at most `max_total_bytes` read in all, more
//!   fails the refresh. Sizes come from the listing, so nothing over a limit is read. Only regular files
//!   are read: a symbolic link or a submodule named like an atomic file is skipped and counted.
//! - YAML: each file is loaded by `ace_hunt::yaml`, PyYAML's `safe_load` within a budget: at most
//!   [`MAX_YAML_NODES`] nodes and [`MAX_YAML_TEXT_BYTES`] bytes of text, an alias counted as a copy of what
//!   it names, so an alias bomb runs out of budget, not memory; nesting at most [`MAX_YAML_DEPTH`] deep; a
//!   recursive alias refused. A file over its budget is skipped as unreadable.
//! - what the files build: at most [`MAX_TOTAL_YAML_NODES`] nodes and `max_total_bytes` of text over all of
//!   a commit's files, aliases counted as copies, more fails the refresh. So aliases can't make a refresh
//!   hold more than it may read, and a test holds only what its own file built.
//! - tests: at most `max_tests` in one commit, more fails the refresh. A test's name and its technique's
//!   name are kept to 512 characters and its executor's to 64, ace3's columns, so one long line of a file
//!   isn't stored once for each of its tests.
//! - what's shown: a path, a name, a reason or an error that came from the repository or from git has its
//!   control characters replaced before it's logged, stored on the repository's row or printed
//!   ([`printable`]), so a repository can't write to an operator's terminal.
//!
//! A refresh that fails stores nothing but its error, and the catalog keeps the tests of the commit it
//! last read.
//!
//! **What differs from ace3's.**
//! - ace3 reads the working tree `service_git` keeps at a `git_repo_*` section's `local_path`. ace-rs has no
//!   such sections or service: a repository is the overlay's entry, and its tests are read from one commit
//!   of the mirror. So nothing can move while it's read, and ace3's check for that
//!   (`test_a_commit_that_moves_while_reading_stores_nothing`) has no counterpart; and ace3's errors for a
//!   missing section or checkout are a fetch that fails.
//! - A test's guid is a uuid here (`svs.catalog_tests.guid`), as a run's `test_guid` is, where ace3 keeps
//!   any text of up to 36 characters. One that isn't a uuid is skipped and counted, as is a technique of
//!   more than 32 characters, which ace3's column refuses, failing its whole refresh, and a test holding a
//!   NUL character, which Postgres can't store.
//! - ace3 globs with the file system, which follows symbolic links; see *Bounds*.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use ace_hunt::correlate::scripts::{py_str, strip};
use ace_hunt::value::Value;
use ace_hunt::yaml::{Budget, Limits};
use ace_sdk::{Secret, Secrets, SvsCatalogRepository, SvsCatalogSection};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use uuid::Uuid;

use super::attack::normalize_platform;
use super::yara::repository::{Mirror, TreeEntry};

/// The directory of a repository that holds its atomics.
pub const ATOMICS_DIR: &str = "atomics";
/// The most `git ls-tree` may print for `atomics/`: about 600,000 entries. Atomic Red Team's prints 183 KB.
pub const MAX_LISTING_BYTES: u64 = 64 << 20;
/// The most YAML nodes one atomic file may build, aliases counted as copies. Atomic Red Team's largest
/// builds 2,092.
pub const MAX_YAML_NODES: usize = 500_000;
/// The most bytes of text one atomic file may build, aliases counted as copies. Atomic Red Team's largest
/// builds 90 KB.
pub const MAX_YAML_TEXT_BYTES: usize = 64 << 20;
/// The deepest nesting of collections in an atomic file. Atomic Red Team's nest 5.
pub const MAX_YAML_DEPTH: usize = 64;
/// The most YAML nodes all of a commit's atomic files may build, aliases counted as copies. Atomic Red
/// Team's build 69,000, and 2.1 MB of text.
pub const MAX_TOTAL_YAML_NODES: usize = 2_000_000;
/// The longest test name and technique name kept, in characters: ace3's columns.
const MAX_NAME_CHARS: usize = 512;
/// The longest executor name kept, in characters: ace3's column.
const MAX_EXECUTOR_CHARS: usize = 64;
/// The longest technique kept, in characters: `svs.catalog_tests.technique`, and ace3's column.
const MAX_TECHNIQUE_CHARS: usize = 32;
/// The longest error kept on a repository's row.
const MAX_ERROR_CHARS: usize = 4096;

/// What a repository's row says once it's taken out of `svs.catalog.repositories`: ace3's
/// `RETIRED_ERROR`. It makes the next refresh read the repository again if it's listed again, whatever
/// its commit.
pub const RETIRED_ERROR: &str = "no longer in svs.catalog.repositories; its tests were removed";

/// The repository can't be read; the message is stored on its row. It never holds the repository's URL.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct CatalogError(pub String);

/// What one refresh may take from a repository (the module's *Bounds*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogLimits {
    pub max_files: u64,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_tests: u64,
}

impl Default for CatalogLimits {
    fn default() -> Self {
        CatalogConfig::default().limits
    }
}

/// The catalog's settings, from the overlay's `svs.catalog` (`ace_sdk::SvsCatalogSection`), checked.
#[derive(Debug, Clone, PartialEq)]
pub struct CatalogConfig {
    pub repositories: BTreeMap<String, SvsCatalogRepository>,
    /// Each repository's SSH private key, by the repository's name, for those whose `ssh_key` names a
    /// secret that was resolved (`with_secrets`). Its `Debug` output hides the keys.
    pub ssh_keys: BTreeMap<String, Secret>,
    pub fetch_timeout: Duration,
    pub mirror_dir: PathBuf,
    pub limits: CatalogLimits,
}

impl Default for CatalogConfig {
    fn default() -> Self {
        CatalogConfig::from_section(&SvsCatalogSection::default()).expect("the defaults are valid")
    }
}

impl CatalogConfig {
    /// The settings `section` gives, or why they can't run.
    pub fn from_section(section: &SvsCatalogSection) -> Result<CatalogConfig, String> {
        section.check()?;
        Ok(CatalogConfig {
            repositories: section.repositories.clone(),
            ssh_keys: BTreeMap::new(),
            fetch_timeout: Duration::from_secs(section.fetch_timeout_seconds),
            // beside the validation mirrors, never among them: a rule repository and a catalog repository
            // may share a name
            mirror_dir: section.mirror_dir.clone().unwrap_or_else(|| {
                std::env::temp_dir()
                    .join("ace-rs-svs")
                    .join("catalog-mirrors")
            }),
            limits: CatalogLimits {
                max_files: section.max_files,
                max_file_bytes: section.max_file_bytes,
                max_total_bytes: section.max_total_bytes,
                max_tests: section.max_tests,
            },
        })
    }

    /// The names of the secrets the repositories' `ssh_key`s name: what a process that fetches resolves
    /// from the overlay's `secrets:`, and no others (PLAN.md 2.24).
    pub fn secret_names(&self) -> Vec<&str> {
        self.repositories
            .values()
            .filter_map(|repository| repository.ssh_key.as_deref())
            .collect()
    }

    /// The settings with each repository's SSH key taken from `secrets` by the name its `ssh_key` gives.
    pub fn with_secrets(mut self, secrets: &Secrets) -> Self {
        self.ssh_keys = self
            .repositories
            .iter()
            .filter_map(|(name, repository)| {
                let secret = secrets.get(repository.ssh_key.as_deref()?)?;
                Some((name.clone(), secret.clone()))
            })
            .collect();
        self
    }

    /// The SSH key `repository`'s mirror fetches with: None when it names none, and an error when it names
    /// a secret that isn't set, so a fetch never goes ahead without the key the site configured. The error
    /// names the secret, never its value.
    pub fn ssh_key(&self, repository: &str) -> Result<Option<Secret>, String> {
        let Some(secret) = self
            .repositories
            .get(repository)
            .and_then(|config| config.ssh_key.as_deref())
        else {
            return Ok(None);
        };
        match self.ssh_keys.get(repository) {
            Some(key) => Ok(Some(key.clone())),
            None => Err(format!(
                "repository {repository}: its ssh_key, the secret {secret}, isn't set"
            )),
        }
    }
}

/// `text` with its control characters replaced, but line breaks and tabs: what came from a repository or
/// from git, made safe to log and to print on a terminal.
pub fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                char::REPLACEMENT_CHARACTER
            } else {
                c
            }
        })
        .collect()
}

/// `printable`, on one line.
fn printable_line(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                char::REPLACEMENT_CHARACTER
            } else {
                c
            }
        })
        .collect()
}

/// A repository's URL without the credentials it may carry (`https://token@host/...`), for showing: ace3's
/// `strip_url_credentials`. A path or an scp-style address (`git@host:path`), which holds no secret, is
/// left as it is.
pub fn strip_url_credentials(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    match authority.rsplit_once('@') {
        Some((_, host)) => format!("{scheme}://{host}{tail}"),
        None => url.to_owned(),
    }
}

// ---- parsing ----

/// One test as its atomic file defines it: ace3's `CatalogEntry`.
#[derive(Debug, Clone, PartialEq)]
pub struct CatalogEntry {
    pub guid: Uuid,
    pub technique: String,
    pub technique_name: Option<String>,
    pub name: String,
    pub description: Option<String>,
    /// Its `supported_platforms`, lower case, as written.
    pub platforms: Vec<String>,
    pub executor: Option<String>,
    /// The test's own entry in the atomic file.
    pub test: serde_json::Value,
    /// The sha256 of the entry, canonically serialized (`content_hash`).
    pub content_hash: String,
    /// Where it came from, relative to the repository's top.
    pub path: String,
}

/// Something a refresh didn't read: a file, or one test of a file. Its text is `printable`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skipped {
    pub path: String,
    /// The test's name, for a test; None for a whole file.
    pub name: Option<String>,
    pub reason: String,
}

impl Skipped {
    fn new(path: &str, name: Option<&str>, reason: impl Into<String>) -> Skipped {
        Skipped {
            path: printable_line(path),
            name: name.map(printable_line),
            reason: printable(&reason.into()),
        }
    }
}

/// What parsing a commit's atomic files gave: ace3's `ParseResult`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParseResult {
    pub entries: Vec<CatalogEntry>,
    pub skipped: Vec<Skipped>,
    /// The YAML nodes the files built, aliases counted as copies.
    pub built_nodes: usize,
    /// The bytes of text the files built, aliases counted as copies.
    pub built_text_bytes: usize,
}

/// One atomic file of a commit: its content, or why it wasn't read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicFile {
    /// Relative to the repository's top, such as `atomics/T1003/T1003.yaml`.
    pub path: String,
    pub content: Result<Vec<u8>, String>,
}

fn key_text(key: &Value) -> String {
    // a key as json.dumps writes one that isn't a string
    match key {
        Value::Str(s) => s.clone(),
        Value::Bool(true) => "true".to_owned(),
        Value::Bool(false) => "false".to_owned(),
        Value::Null => "null".to_owned(),
        other => other.key_text(),
    }
}

fn canonical(value: &Value, out: &mut String) {
    use ace_hunt::render::json::quote;
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(i) => out.push_str(&i.to_string()),
        Value::Float(f) if f.is_nan() => out.push_str("NaN"),
        Value::Float(f) if f.is_infinite() => {
            out.push_str(if *f > 0.0 { "Infinity" } else { "-Infinity" });
        }
        Value::Float(f) => out.push_str(&ace_hunt::render::py::float_repr(*f)),
        Value::Str(s) | Value::Date(s) => quote(s, out),
        // json.dumps(default=str): str() of a datetime has a space where its ISO form has a T
        Value::DateTime(_) => {
            let iso = value.to_json();
            let iso = iso.as_str().unwrap_or_default();
            quote(&iso.replacen('T', " ", 1), out);
        }
        Value::Seq(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                canonical(item, out);
            }
            out.push(']');
        }
        Value::Map(map) => {
            let mut entries: Vec<(String, &Value)> =
                map.iter().map(|(k, v)| (key_text(k), v)).collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                quote(key, out);
                out.push(':');
                canonical(item, out);
            }
            out.push('}');
        }
    }
}

/// The sha256 of a test's entry, canonically serialized, so it changes exactly when the test does: ace3's
/// `content_hash`, the hash of `json.dumps(test, sort_keys=True, separators=(",", ":"), default=str)`.
pub fn content_hash(test: &Value) -> String {
    let mut text = String::new();
    canonical(test, &mut text);
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// ace3's `_text`: Python's `str()` of a value, stripped, or None for nothing.
fn text_of(value: Option<&Value>) -> Option<String> {
    match value {
        None | Some(Value::Null) => None,
        Some(value) => Some(strip(&py_str(value)).to_owned()).filter(|text| !text.is_empty()),
    }
}

/// Python's truth of a loaded value.
fn truthy(value: &Value) -> bool {
    value.truthy()
}

fn has_nul(value: &Value) -> bool {
    match value {
        Value::Str(s) | Value::Date(s) | Value::DateTime(s) => s.contains('\0'),
        Value::Seq(items) => items.iter().any(has_nul),
        Value::Map(map) => map.iter().any(|(k, v)| has_nul(k) || has_nul(v)),
        _ => false,
    }
}

fn decode(bytes: &[u8]) -> Result<String, String> {
    // PyYAML reads UTF-16 with a byte order mark, and UTF-8 otherwise
    let utf16 = |units: Vec<u16>| {
        String::from_utf16(&units).map_err(|_| "'utf-16' codec can't decode it".to_owned())
    };
    match bytes {
        [0xff, 0xfe, rest @ ..] => utf16(
            rest.chunks(2)
                .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                .collect(),
        ),
        [0xfe, 0xff, rest @ ..] => utf16(
            rest.chunks(2)
                .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                .collect(),
        ),
        _ => {
            let text = std::str::from_utf8(bytes).map_err(|e| {
                format!(
                    "'utf-8' codec can't decode the byte at position {}",
                    e.valid_up_to()
                )
            })?;
            Ok(text.strip_prefix('\u{feff}').unwrap_or(text).to_owned())
        }
    }
}

/// Adds the tests of one atomic file to `result`: ace3's `parse_atomic_file`.
pub fn parse_atomic_file(file: &AtomicFile, result: &mut ParseResult) {
    let path = file.path.as_str();
    let bytes = match &file.content {
        Ok(bytes) => bytes,
        Err(reason) => {
            result.skipped.push(Skipped::new(path, None, reason));
            return;
        }
    };
    let mut budget = Budget::new(Limits {
        max_file_bytes: u64::MAX,
        max_nodes: MAX_YAML_NODES,
        max_text_bytes: MAX_YAML_TEXT_BYTES,
        max_depth: MAX_YAML_DEPTH,
        max_files: 1,
    });
    let document = match decode(bytes)
        .and_then(|text| ace_hunt::yaml::load(&text, path, &mut budget).map_err(|e| e.message))
    {
        Ok(document) => document,
        Err(e) => {
            result
                .skipped
                .push(Skipped::new(path, None, format!("unreadable: {e}")));
            return;
        }
    };
    result.built_nodes = result.built_nodes.saturating_add(document.nodes());
    result.built_text_bytes = result
        .built_text_bytes
        .saturating_add(document.text_bytes());
    let tests = match document.as_map().and_then(|map| map.get("atomic_tests")) {
        Some(Value::Seq(tests)) => tests,
        _ => {
            result.skipped.push(Skipped::new(
                path,
                None,
                "not an atomic file (no atomic_tests list)",
            ));
            return;
        }
    };
    let document = document.as_map().expect("checked above");
    // the technique's directory, when the file doesn't name its technique
    let directory = path.rsplit('/').nth(1).unwrap_or_default();
    let technique = text_of(document.get("attack_technique"))
        .unwrap_or_else(|| directory.to_owned())
        .to_uppercase();
    let technique_name = text_of(document.get("display_name"))
        .map(|name| name.chars().take(MAX_NAME_CHARS).collect::<String>());

    for (index, test) in tests.iter().enumerate() {
        let Some(map) = test.as_map() else {
            result.skipped.push(Skipped::new(
                path,
                None,
                format!("atomic test {index} is not a mapping"),
            ));
            continue;
        };
        let name = text_of(map.get("name")).unwrap_or_else(|| format!("atomic test {index}"));
        let skip = |result: &mut ParseResult, reason: String| {
            result.skipped.push(Skipped::new(path, Some(&name), reason));
        };
        let Some(guid) = text_of(map.get("auto_generated_guid")) else {
            skip(result, "no auto_generated_guid".to_owned());
            continue;
        };
        let guid = guid.to_lowercase();
        let parsed = (guid.len() == 36)
            .then(|| Uuid::try_parse(&guid).ok())
            .flatten();
        let Some(guid) = parsed else {
            skip(
                result,
                format!("auto_generated_guid {guid:?} is not a uuid"),
            );
            continue;
        };
        if technique.is_empty() || technique.chars().count() > MAX_TECHNIQUE_CHARS {
            skip(
                result,
                format!(
                    "its technique is {} characters, not 1 to {MAX_TECHNIQUE_CHARS}",
                    technique.chars().count()
                ),
            );
            continue;
        }
        if has_nul(test) || technique.contains('\0') {
            skip(result, "it holds a NUL character".to_owned());
            continue;
        }
        if technique_name
            .as_deref()
            .is_some_and(|name| name.contains('\0'))
        {
            skip(
                result,
                "its technique's name holds a NUL character".to_owned(),
            );
            continue;
        }

        let platforms = match map.get("supported_platforms") {
            Some(Value::Seq(items)) => items.clone(),
            Some(other) if truthy(other) => vec![other.clone()],
            _ => Vec::new(),
        };
        let platforms: Vec<String> = platforms
            .iter()
            .map(|platform| strip(&py_str(platform)).to_lowercase())
            .filter(|platform| !platform.is_empty())
            .collect();
        let executor = match map.get("executor") {
            Some(Value::Map(executor)) => text_of(executor.get("name"))
                .map(|name| name.chars().take(MAX_EXECUTOR_CHARS).collect()),
            _ => None,
        };
        result.entries.push(CatalogEntry {
            guid,
            technique: technique.clone(),
            technique_name: technique_name.clone(),
            name: name.chars().take(MAX_NAME_CHARS).collect(),
            description: text_of(map.get("description")),
            platforms,
            executor,
            test: test.to_json(),
            content_hash: content_hash(test),
            path: path.to_owned(),
        });
    }
}

/// Every test in `files`, a commit's atomic files, in the order of their paths: ace3's `parse_atomics`. A
/// GUID seen twice keeps its first test; the others are skipped. More than `max_tests` tests is an error,
/// and so is building more than the files may hold (the module's *Bounds*).
pub fn parse_atomics(
    mut files: Vec<AtomicFile>,
    limits: &CatalogLimits,
) -> Result<ParseResult, CatalogError> {
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let mut result = ParseResult::default();
    for file in &files {
        parse_atomic_file(file, &mut result);
        if result.entries.len() as u64 > limits.max_tests {
            return Err(CatalogError(format!(
                "the commit defines more than {} tests (svs.catalog.max_tests)",
                limits.max_tests
            )));
        }
        if result.built_nodes > MAX_TOTAL_YAML_NODES
            || result.built_text_bytes as u64 > limits.max_total_bytes
        {
            return Err(CatalogError(format!(
                "the commit's atomic files build more than {MAX_TOTAL_YAML_NODES} YAML nodes or {} bytes \
                 of text, aliases counted as copies (svs.catalog.max_total_bytes)",
                limits.max_total_bytes
            )));
        }
    }
    let mut seen = BTreeSet::new();
    let mut unique = Vec::with_capacity(result.entries.len());
    for entry in result.entries {
        if !seen.insert(entry.guid) {
            result.skipped.push(Skipped::new(
                &entry.path,
                Some(&entry.name),
                format!(
                    "auto_generated_guid {} is used by an earlier test",
                    entry.guid
                ),
            ));
            continue;
        }
        unique.push(entry);
    }
    result.entries = unique;
    Ok(result)
}

/// Whether `path` is an atomic file: `atomics/T*/T*.yaml`, ace3's glob.
pub fn is_atomic_path(path: &str) -> bool {
    let mut parts = path.split('/');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(ATOMICS_DIR), Some(dir), Some(file), None)
            if dir.starts_with('T') && file.starts_with('T') && file.ends_with(".yaml")
    )
}

/// An atomic file's path, with the object to read or why it isn't read.
pub type SelectedFile = (String, Result<String, String>);

/// The atomic files among a commit's `entries`, each to be read or skipped with its reason, within the
/// limits (the module's *Bounds*). Returns each file's path with the object to read, or why it isn't read.
pub fn select_atomic_files(
    entries: &[TreeEntry],
    limits: &CatalogLimits,
) -> Result<Vec<SelectedFile>, CatalogError> {
    let mut selected = Vec::new();
    let mut total = 0u64;
    for entry in entries
        .iter()
        .filter(|e| e.kind != "tree" && is_atomic_path(&e.path))
    {
        if selected.len() as u64 >= limits.max_files {
            return Err(CatalogError(format!(
                "the commit has more than {} atomic files (svs.catalog.max_files)",
                limits.max_files
            )));
        }
        let read = if !entry.is_regular_file() {
            Err(match entry.mode.as_str() {
                "120000" => "a symbolic link: only regular files are read".to_owned(),
                "160000" => "a submodule: only regular files are read".to_owned(),
                mode => format!("not a regular file (mode {mode})"),
            })
        } else {
            match entry.size {
                Some(size) if size > limits.max_file_bytes => {
                    Err(format!("larger than {} bytes", limits.max_file_bytes))
                }
                Some(size) => {
                    total = total.saturating_add(size);
                    if total > limits.max_total_bytes {
                        return Err(CatalogError(format!(
                            "the commit's atomic files are more than {} bytes (svs.catalog.max_total_bytes)",
                            limits.max_total_bytes
                        )));
                    }
                    Ok(entry.object.clone())
                }
                None => Err("git gave no size for it".to_owned()),
            }
        };
        selected.push((entry.path.clone(), read));
    }
    Ok(selected)
}

/// What reading a repository gave: the commit its branch is at, and its tests unless that commit is the
/// one already read.
#[derive(Debug, Clone, PartialEq)]
pub struct RepositoryRead {
    pub commit: String,
    pub parsed: Option<ParseResult>,
}

/// Fetches `repository`'s branch into its mirror and reads the tests of the commit it's at: every
/// `atomics/T*/T*.yaml` of that commit, from git's objects. A commit equal to `already_read` isn't read
/// again. Blocking: it runs git.
pub fn read_repository(
    config: &CatalogConfig,
    repository: &str,
    already_read: Option<&str>,
) -> Result<RepositoryRead, CatalogError> {
    let failed = |e: super::yara::repository::RepositoryError| CatalogError(e.0);
    let Some(settings) = config.repositories.get(repository) else {
        return Err(CatalogError(format!(
            "{repository} is not in svs.catalog.repositories"
        )));
    };
    let key = config.ssh_key(repository).map_err(CatalogError)?;
    let mirror = Mirror::new(
        repository,
        &settings.url,
        &config.mirror_dir,
        config.fetch_timeout,
    )
    .with_ssh_key(key);
    let _lock = mirror.lock().map_err(failed)?;
    mirror.ensure(&[&settings.branch], &[]).map_err(failed)?;
    let commit = mirror
        .head(&settings.branch)
        .map_err(failed)?
        .ok_or_else(|| {
            CatalogError(format!(
                "the mirror of {repository} has no branch {}",
                settings.branch
            ))
        })?;
    if already_read == Some(commit.as_str()) {
        return Ok(RepositoryRead {
            commit,
            parsed: None,
        });
    }
    let entries = mirror
        .list_tree(
            &commit,
            ATOMICS_DIR,
            MAX_LISTING_BYTES,
            config.fetch_timeout,
        )
        .map_err(failed)?;
    let selected = select_atomic_files(&entries, &config.limits)?;
    let objects: Vec<String> = selected
        .iter()
        .filter_map(|(_, read)| read.as_ref().ok().cloned())
        .collect();
    let mut contents = mirror
        .read_files(&objects, config.limits.max_file_bytes, config.fetch_timeout)
        .map_err(failed)?
        .into_iter();
    let files = selected
        .into_iter()
        .map(|(path, read)| AtomicFile {
            path,
            content: read.map(|_| contents.next().unwrap_or_default()),
        })
        .collect();
    let parsed = parse_atomics(files, &config.limits)?;
    Ok(RepositoryRead {
        commit,
        parsed: Some(parsed),
    })
}

// ---- storing ----

/// What one refresh of one repository did: ace3's `RefreshResult`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RefreshResult {
    pub repository: String,
    pub commit: Option<String>,
    /// False when the commit was already read, or the refresh failed.
    pub refreshed: bool,
    pub tests: i64,
    pub added: i64,
    pub changed: i64,
    pub removed: i64,
    pub skipped: Vec<Skipped>,
    pub error: Option<String>,
    /// The repository is no longer in `svs.catalog.repositories` and its tests were removed.
    pub retired: bool,
}

/// A repository's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryRow {
    pub name: String,
    pub commit: Option<String>,
    pub refreshed_at: Option<DateTime<Utc>>,
    pub test_count: i32,
    pub skipped_count: i32,
    pub error: Option<String>,
}

/// A repository's row as it is, without a lock, or None before its first refresh.
pub async fn repository_row(
    conn: &mut PgConnection,
    repository: &str,
) -> Result<Option<RepositoryRow>, sqlx::Error> {
    sqlx::query_as!(
        RepositoryRow,
        "SELECT name, commit, refreshed_at, test_count, skipped_count, error
         FROM svs.catalog_repositories WHERE name = $1",
        repository,
    )
    .fetch_optional(conn)
    .await
}

/// The repository's row, locked until the transaction ends, and made on first use: ace3's
/// `_lock_repository`.
async fn lock_repository(
    conn: &mut PgConnection,
    repository: &str,
) -> Result<RepositoryRow, sqlx::Error> {
    sqlx::query!(
        "INSERT INTO svs.catalog_repositories (name) VALUES ($1) ON CONFLICT (name) DO NOTHING",
        repository,
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query_as!(
        RepositoryRow,
        "SELECT name, commit, refreshed_at, test_count, skipped_count, error
         FROM svs.catalog_repositories WHERE name = $1 FOR UPDATE",
        repository,
    )
    .fetch_one(conn)
    .await
}

fn bounded_error(error: &str) -> String {
    error.chars().take(MAX_ERROR_CHARS).collect()
}

/// Puts `error` on the repository's row: ace3's `_record_error`. Returns whether the row changed, which it
/// doesn't when it already says so.
pub async fn record_error(
    conn: &mut PgConnection,
    repository: &str,
    error: &str,
) -> Result<bool, sqlx::Error> {
    let error = bounded_error(error);
    let row = lock_repository(conn, repository).await?;
    if row.error.as_deref() == Some(error.as_str()) {
        return Ok(false);
    }
    sqlx::query!(
        "UPDATE svs.catalog_repositories SET error = $2 WHERE name = $1",
        repository,
        error,
    )
    .execute(conn)
    .await?;
    Ok(true)
}

struct ExistingTest {
    id: i64,
    guid: Uuid,
    repository: String,
    technique: String,
    technique_name: Option<String>,
    name: String,
    description: Option<String>,
    platforms: Vec<String>,
    executor: Option<String>,
    content_hash: String,
    path: String,
    removed: bool,
}

/// Stores a commit's tests as the repository's, under its row's lock: ace3's `_store`. A test that's new
/// is added, one whose entry or place changed is updated, and one of the repository's that the commit
/// doesn't have is marked removed. A test keeps the commit it was last changed in, so a new commit of the
/// repository doesn't touch the tests it didn't change, and a GUID that belongs to a live test of another
/// repository is skipped. `result` gains the counts and what was skipped.
pub async fn store(
    conn: &mut PgConnection,
    repository: &str,
    commit: &str,
    parsed: &ParseResult,
    result: &mut RefreshResult,
) -> Result<(), sqlx::Error> {
    lock_repository(conn, repository).await?;
    let guids: Vec<Uuid> = parsed.entries.iter().map(|entry| entry.guid).collect();
    let existing: BTreeMap<Uuid, ExistingTest> = sqlx::query_as!(
        ExistingTest,
        r#"SELECT id, guid, repository, technique, technique_name, name, description, platforms, executor,
                  content_hash, path, removed_at IS NOT NULL AS "removed!"
           FROM svs.catalog_tests
           WHERE repository = $1 OR guid = ANY ($2)
           FOR UPDATE"#,
        repository,
        &guids,
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|test| (test.guid, test))
    .collect();

    result.skipped = parsed.skipped.clone();
    let mut stored: BTreeSet<Uuid> = BTreeSet::new();
    for entry in &parsed.entries {
        match existing.get(&entry.guid) {
            Some(test) if test.repository != repository && !test.removed => {
                result.skipped.push(Skipped::new(
                    &entry.path,
                    Some(&entry.name),
                    format!(
                        "auto_generated_guid {} belongs to a test of {}",
                        entry.guid, test.repository
                    ),
                ));
                continue;
            }
            Some(test) => {
                let same = test.repository == repository
                    && test.technique == entry.technique
                    && test.technique_name == entry.technique_name
                    && test.name == entry.name
                    && test.description == entry.description
                    && test.platforms == entry.platforms
                    && test.executor == entry.executor
                    && test.content_hash == entry.content_hash
                    && test.path == entry.path
                    && !test.removed;
                if !same {
                    // the commit moves only with the test's own entry
                    sqlx::query!(
                        "UPDATE svs.catalog_tests
                         SET repository = $2, technique = $3, technique_name = $4, name = $5,
                             description = $6, platforms = $7, executor = $8, test = $9,
                             commit = CASE WHEN content_hash = $10 THEN commit ELSE $11 END,
                             content_hash = $10, path = $12, removed_at = NULL
                         WHERE id = $1",
                        test.id,
                        repository,
                        entry.technique,
                        entry.technique_name,
                        entry.name,
                        entry.description,
                        &entry.platforms,
                        entry.executor,
                        entry.test,
                        entry.content_hash,
                        commit,
                        entry.path,
                    )
                    .execute(&mut *conn)
                    .await?;
                    result.changed += 1;
                }
            }
            None => {
                sqlx::query!(
                    "INSERT INTO svs.catalog_tests
                         (guid, repository, technique, technique_name, name, description, platforms,
                          executor, test, content_hash, commit, path, first_seen_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now())",
                    entry.guid,
                    repository,
                    entry.technique,
                    entry.technique_name,
                    entry.name,
                    entry.description,
                    &entry.platforms,
                    entry.executor,
                    entry.test,
                    entry.content_hash,
                    commit,
                    entry.path,
                )
                .execute(&mut *conn)
                .await?;
                result.added += 1;
            }
        }
        stored.insert(entry.guid);
    }

    let gone: Vec<i64> = existing
        .values()
        .filter(|test| {
            test.repository == repository && !stored.contains(&test.guid) && !test.removed
        })
        .map(|test| test.id)
        .collect();
    if !gone.is_empty() {
        sqlx::query!(
            "UPDATE svs.catalog_tests SET removed_at = now() WHERE id = ANY ($1)",
            &gone,
        )
        .execute(&mut *conn)
        .await?;
    }
    result.removed = gone.len() as i64;

    let count = |n: usize| i32::try_from(n).unwrap_or(i32::MAX);
    sqlx::query!(
        "UPDATE svs.catalog_repositories
         SET commit = $2, refreshed_at = now(), test_count = $3, skipped_count = $4, error = NULL
         WHERE name = $1",
        repository,
        commit,
        count(stored.len()),
        count(result.skipped.len()),
    )
    .execute(conn)
    .await?;
    result.tests = stored.len() as i64;
    result.refreshed = true;
    Ok(())
}

/// Removes the tests of a repository that is no longer in `svs.catalog.repositories`: ace3's
/// `retire_repository`. They keep their rows and runs, as a test that disappears does. Returns how many
/// were removed.
pub async fn retire(conn: &mut PgConnection, repository: &str) -> Result<i64, sqlx::Error> {
    lock_repository(conn, repository).await?;
    let removed = sqlx::query!(
        "UPDATE svs.catalog_tests SET removed_at = now()
         WHERE repository = $1 AND removed_at IS NULL",
        repository,
    )
    .execute(&mut *conn)
    .await?
    .rows_affected();
    sqlx::query!(
        "UPDATE svs.catalog_repositories SET test_count = 0, error = $2 WHERE name = $1",
        repository,
        RETIRED_ERROR,
    )
    .execute(conn)
    .await?;
    Ok(removed as i64)
}

/// The repositories that still have tests in the catalog and aren't in `configured`, sorted: what a
/// refresh retires.
pub async fn unconfigured(
    conn: &mut PgConnection,
    configured: &[String],
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        "SELECT DISTINCT repository FROM svs.catalog_tests
         WHERE removed_at IS NULL AND NOT repository = ANY ($1)
         ORDER BY repository",
        configured,
    )
    .fetch_all(conn)
    .await
}

/// A catalog repository as `ace svs catalog status` and the API show it: ace3's `RepositoryStatus`. Every
/// repository in `svs.catalog.repositories`, and every one that has a row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RepositoryStatus {
    pub name: String,
    /// It is in `svs.catalog.repositories`.
    pub configured: bool,
    /// From its overlay entry, None without one; it never carries credentials.
    pub git_url: Option<String>,
    pub branch: Option<String>,
    /// The commit the catalog holds and when it was read, None until it is first read.
    pub commit: Option<String>,
    pub refreshed_at: Option<DateTime<Utc>>,
    pub test_count: i64,
    pub skipped_count: i64,
    /// Tests of the repository removed from the catalog since they were first read.
    pub removed_count: i64,
    /// Why the last refresh failed, None when it succeeded or the repository is retired.
    pub error: Option<String>,
    /// Taken out of `svs.catalog.repositories`, so its tests were removed.
    pub retired: bool,
}

/// Every catalog repository's status, by name: ace3's `repository_status`.
pub async fn repository_status(
    conn: &mut PgConnection,
    config: &CatalogConfig,
) -> Result<Vec<RepositoryStatus>, sqlx::Error> {
    let rows: BTreeMap<String, RepositoryRow> = sqlx::query_as!(
        RepositoryRow,
        "SELECT name, commit, refreshed_at, test_count, skipped_count, error
         FROM svs.catalog_repositories",
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|row| (row.name.clone(), row))
    .collect();
    let removed: BTreeMap<String, i64> = sqlx::query!(
        r#"SELECT repository, count(*) AS "count!" FROM svs.catalog_tests
           WHERE removed_at IS NOT NULL GROUP BY repository"#,
    )
    .fetch_all(conn)
    .await?
    .into_iter()
    .map(|row| (row.repository, row.count))
    .collect();

    let names: BTreeSet<&String> = config.repositories.keys().chain(rows.keys()).collect();
    Ok(names
        .into_iter()
        .map(|name| {
            let row = rows.get(name);
            let settings = config.repositories.get(name);
            let error = row.and_then(|row| row.error.clone());
            let retired = error.as_deref() == Some(RETIRED_ERROR);
            RepositoryStatus {
                name: name.clone(),
                configured: settings.is_some(),
                git_url: settings.map(|s| strip_url_credentials(&s.url)),
                branch: settings.map(|s| s.branch.clone()),
                commit: row.and_then(|row| row.commit.clone()),
                refreshed_at: row.and_then(|row| row.refreshed_at),
                test_count: row.map_or(0, |row| i64::from(row.test_count)),
                skipped_count: row.map_or(0, |row| i64::from(row.skipped_count)),
                removed_count: removed.get(name).copied().unwrap_or(0),
                error: if retired { None } else { error },
                retired,
            }
        })
        .collect())
}

/// The platforms a run of a test can be on: its `supported_platforms` as platform slugs, sorted. ace3's
/// `platform_slugs`.
pub fn platform_slugs(platforms: &[String]) -> Vec<String> {
    let slugs: BTreeSet<String> = platforms.iter().map(|p| normalize_platform(p)).collect();
    slugs.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUID_A: &str = "aaaaaaaa-1111-4111-8111-111111111111";
    const GUID_B: &str = "bbbbbbbb-2222-4222-8222-222222222222";
    const GUID_C: &str = "cccccccc-3333-4333-8333-333333333333";

    /// One test of an atomic file, as ace3's test helper `_test` writes it.
    fn test(name: &str, guid: Option<&str>, platform: &str, executor: &str) -> String {
        let guid = guid.map_or(String::new(), |g| format!("  auto_generated_guid: {g}\n"));
        format!(
            "- name: {name}\n{guid}  description: |\n    {name} does a thing\n  supported_platforms:\n  - {platform}\n  \
             input_arguments:\n    output_file:\n      description: where\n      type: path\n      default: out.txt\n  \
             executor:\n    name: {executor}\n    command: whoami\n    elevation_required: false\n"
        )
    }

    fn atomic(technique: &str, display_name: &str, tests: &[String]) -> String {
        format!(
            "attack_technique: {technique}\ndisplay_name: {display_name}\natomic_tests:\n{}",
            tests.concat()
        )
    }

    fn file(path: &str, content: &str) -> AtomicFile {
        AtomicFile {
            path: path.to_owned(),
            content: Ok(content.as_bytes().to_vec()),
        }
    }

    fn reasons(result: &ParseResult) -> BTreeMap<(String, Option<String>), String> {
        result
            .skipped
            .iter()
            .map(|s| ((s.path.clone(), s.name.clone()), s.reason.clone()))
            .collect()
    }

    /// test_catalog.py's `test_parse_atomics`: tests come in the order of their files' paths with their
    /// technique, name, platforms, executor and description; a test with no guid, a guid seen again, a
    /// file that isn't YAML and one that isn't an atomic file are each skipped with the reason. ace3's
    /// last two files, which its glob doesn't match, are `the_glob_is_atomics_t_t_yaml`.
    #[test]
    fn parse_atomics_reads_the_tests() {
        let files = vec![
            file(
                "atomics/T1059.001/T1059.001.yaml",
                &atomic(
                    "T1059.001",
                    "PowerShell",
                    &[
                        test("Mimikatz", Some(GUID_A), "windows", "powershell"),
                        test("No guid", None, "windows", "powershell"),
                    ],
                ),
            ),
            file(
                "atomics/T1003/T1003.yaml",
                &atomic(
                    "T1003",
                    "OS Credential Dumping",
                    &[test("Dump", Some(&GUID_B.to_uppercase()), "Linux", "sh")],
                ),
            ),
            // the same guid again: the first file read keeps it
            file(
                "atomics/T1105/T1105.yaml",
                &atomic(
                    "T1105",
                    "Ingress Tool Transfer",
                    &[test("Copy", Some(GUID_A), "windows", "powershell")],
                ),
            ),
            file("atomics/T1106/T1106.yaml", "{not yaml: ["),
            file("atomics/T1107/T1107.yaml", "just a string\n"),
        ];
        let result = parse_atomics(files, &CatalogLimits::default()).expect("parses");

        let listed: Vec<(String, &str, &str)> = result
            .entries
            .iter()
            .map(|e| (e.guid.to_string(), e.technique.as_str(), e.name.as_str()))
            .collect();
        assert_eq!(
            listed,
            [
                (GUID_B.to_owned(), "T1003", "Dump"),
                (GUID_A.to_owned(), "T1059.001", "Mimikatz"),
            ]
        );
        let dump = &result.entries[0];
        assert_eq!(
            dump.technique_name.as_deref(),
            Some("OS Credential Dumping")
        );
        assert_eq!(dump.platforms, ["linux"]);
        assert_eq!(dump.executor.as_deref(), Some("sh"));
        assert_eq!(dump.path, "atomics/T1003/T1003.yaml");
        assert_eq!(dump.description.as_deref(), Some("Dump does a thing"));
        assert_eq!(dump.test["executor"]["command"], "whoami");
        assert_eq!(dump.test["executor"]["elevation_required"], false);

        let reasons = reasons(&result);
        let reason = |path: &str, name: Option<&str>| {
            reasons[&(path.to_owned(), name.map(str::to_owned))].as_str()
        };
        assert_eq!(
            reason("atomics/T1059.001/T1059.001.yaml", Some("No guid")),
            "no auto_generated_guid"
        );
        assert!(
            reason("atomics/T1105/T1105.yaml", Some("Copy")).contains("used by an earlier test")
        );
        assert!(reason("atomics/T1106/T1106.yaml", None).starts_with("unreadable"));
        assert!(reason("atomics/T1107/T1107.yaml", None).starts_with("not an atomic file"));
    }

    /// The rest of `test_parse_atomics`: only `atomics/T*/T*.yaml` is an atomic file, so an index and a
    /// technique's helper files aren't read, and neither is a symbolic link or a file over the size limit,
    /// which are skipped with the reason.
    #[test]
    fn the_glob_is_atomics_t_t_yaml() {
        for path in [
            "atomics/T1003/T1003.yaml",
            "atomics/T1059.001/T1059.001.yaml",
            "atomics/T1/Tx.yaml",
        ] {
            assert!(is_atomic_path(path), "{path}");
        }
        for path in [
            "atomics/Indexes/index.yaml",
            "atomics/T1059.001/src/helper.yaml",
            "atomics/T1003/T1003.md",
            "atomics/T1003/t1003.yaml",
            "atomics/t1003/T1003.yaml",
            "atomics/T1003.yaml",
            "other/T1003/T1003.yaml",
            "T1003/T1003.yaml",
        ] {
            assert!(!is_atomic_path(path), "{path}");
        }
        let entry = |mode: &str, kind: &str, size: Option<u64>, path: &str| TreeEntry {
            mode: mode.to_owned(),
            kind: kind.to_owned(),
            object: format!("object-of-{path}"),
            size,
            path: path.to_owned(),
        };
        let entries = [
            entry("040000", "tree", None, "atomics/T1003"),
            entry("100644", "blob", Some(10), "atomics/T1003/T1003.yaml"),
            entry("100644", "blob", Some(10), "atomics/T1003/T1003.md"),
            entry("120000", "blob", Some(10), "atomics/T1004/T1004.yaml"),
            entry("160000", "commit", None, "atomics/T1005/T1005.yaml"),
            entry("100644", "blob", Some(101), "atomics/T1006/T1006.yaml"),
            entry("100755", "blob", Some(100), "atomics/T1007/T1007.yaml"),
        ];
        let limits = CatalogLimits {
            max_file_bytes: 100,
            ..CatalogLimits::default()
        };
        let selected = select_atomic_files(&entries, &limits).expect("within the limits");
        let shown: Vec<(&str, Result<&str, &str>)> = selected
            .iter()
            .map(|(path, read)| (path.as_str(), read.as_deref().map_err(String::as_str)))
            .collect();
        assert_eq!(
            shown,
            [
                (
                    "atomics/T1003/T1003.yaml",
                    Ok("object-of-atomics/T1003/T1003.yaml")
                ),
                (
                    "atomics/T1004/T1004.yaml",
                    Err("a symbolic link: only regular files are read")
                ),
                (
                    "atomics/T1005/T1005.yaml",
                    Err("a submodule: only regular files are read")
                ),
                ("atomics/T1006/T1006.yaml", Err("larger than 100 bytes")),
                (
                    "atomics/T1007/T1007.yaml",
                    Ok("object-of-atomics/T1007/T1007.yaml")
                ),
            ]
        );
        // too many files, and too many bytes in all, fail the refresh
        let error = select_atomic_files(
            &entries,
            &CatalogLimits {
                max_files: 4,
                ..limits
            },
        )
        .expect_err("5 files");
        assert!(error.0.contains("more than 4 atomic files"), "{error}");
        let error = select_atomic_files(
            &entries,
            &CatalogLimits {
                max_total_bytes: 109,
                ..limits
            },
        )
        .expect_err("110 bytes");
        assert!(error.0.contains("more than 109 bytes"), "{error}");
    }

    /// test_catalog.py's `test_the_content_hash_follows_the_test_only`: the sha256 of the compact,
    /// key-sorted JSON (`printf '{"a":1,"b":[1,2]}' | sha256sum`), as Python writes it.
    #[test]
    fn the_content_hash_follows_the_test_only() {
        let load = |text: &str| {
            let mut budget = Budget::new(Limits::default());
            ace_hunt::yaml::load(text, "test.yaml", &mut budget).expect("loads")
        };
        assert_eq!(
            content_hash(&load("{b: [1, 2], a: 1}")),
            "8baa73198470c7bb4c3ce142a8fd651affc0310d878bb9bd159e37a573fb4874"
        );
        assert_ne!(content_hash(&load("{a: 1}")), content_hash(&load("{a: 2}")));
        // key order and layout don't change it; a value does
        assert_eq!(
            content_hash(&load("a: 1\nb:\n- 1\n- 2\n")),
            content_hash(&load("{b: [1, 2], a: 1}"))
        );
        // Python's json.dumps: text past ASCII escaped, a float as its repr, a date as str() gives it, and
        // a key that isn't text as JSON writes it (`on` is YAML 1.1's true)
        let mut text = String::new();
        canonical(
            &load(
                "{name: \"caf\\xe9 \\U0001F600\", ratio: 1.50, day: 2024-01-02, at: 2024-01-02T03:04:05, 3: yes, on: ~}",
            ),
            &mut text,
        );
        assert_eq!(
            text,
            "{\"3\":true,\"at\":\"2024-01-02 03:04:05\",\"day\":\"2024-01-02\",\
             \"name\":\"caf\\u00e9 \\ud83d\\ude00\",\"ratio\":1.5,\"true\":null}"
        );
    }

    /// What a hostile or odd atomic file gives: nothing it defines is stored, and each is skipped with
    /// its reason while the files beside it are read.
    #[test]
    fn hostile_files_are_skipped_within_their_bounds() {
        // an alias bomb: nine levels of nine aliases each is 9^9 nodes
        let mut bomb = String::from("a: &a [x, x, x, x, x, x, x, x, x]\n");
        let names = ["a", "b", "c", "d", "e", "f", "g", "h", "i"];
        for pair in names.windows(2) {
            bomb.push_str(&format!(
                "{0}: &{0} [{1}]\n",
                pair[1],
                vec![format!("*{}", pair[0]); 9].join(", ")
            ));
        }
        bomb.push_str("atomic_tests: *i\n");
        let deep = format!("atomic_tests: {}{}\n", "[".repeat(200), "]".repeat(200));
        let files = vec![
            file("atomics/T1001/T1001.yaml", &bomb),
            file("atomics/T1002/T1002.yaml", &deep),
            AtomicFile {
                path: "atomics/T1003/T1003.yaml".to_owned(),
                content: Ok(vec![b'a', b':', b' ', 0xff, 0xfe, b'\n']),
            },
            file(
                "atomics/T1004/T1004.yaml",
                &format!(
                    "atomic_tests:\n- just text\n- name: Not a uuid\n  auto_generated_guid: 1234\n\
                     - name: \"Nul \\0 here\"\n  auto_generated_guid: {GUID_B}\n\
                     - auto_generated_guid: {GUID_C}\n  supported_platforms: Windows\n  executor: none\n"
                ),
            ),
            file(
                "atomics/T1005/T1005.yaml",
                &format!(
                    "attack_technique: {}\natomic_tests:\n- name: Long\n  auto_generated_guid: {GUID_A}\n",
                    "T".repeat(33)
                ),
            ),
            AtomicFile {
                path: "atomics/T1006/T1006.yaml".to_owned(),
                content: Err("larger than 10485760 bytes".to_owned()),
            },
        ];
        let started = std::time::Instant::now();
        let result = parse_atomics(files, &CatalogLimits::default()).expect("parses");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "took {:?}",
            started.elapsed()
        );
        // the one usable test: no attack_technique, so its directory's; no name; a scalar platform
        assert_eq!(result.entries.len(), 1, "{:?}", result.entries);
        let entry = &result.entries[0];
        assert_eq!(
            (
                entry.guid.to_string().as_str(),
                entry.technique.as_str(),
                entry.name.as_str()
            ),
            (GUID_C, "T1004", "atomic test 3")
        );
        assert_eq!(entry.platforms, ["windows"]);
        assert_eq!(entry.executor, None);
        assert_eq!(entry.technique_name, None);

        let reasons = reasons(&result);
        let reason = |path: &str, name: Option<&str>| {
            reasons
                .get(&(path.to_owned(), name.map(str::to_owned)))
                .unwrap_or_else(|| panic!("{path} {name:?} in {reasons:?}"))
                .as_str()
        };
        assert!(
            reason("atomics/T1001/T1001.yaml", None).starts_with("unreadable: ")
                && reason("atomics/T1001/T1001.yaml", None).contains("YAML nodes"),
            "{}",
            reason("atomics/T1001/T1001.yaml", None)
        );
        assert!(reason("atomics/T1002/T1002.yaml", None).starts_with("unreadable: "));
        assert!(reason("atomics/T1003/T1003.yaml", None).starts_with("unreadable: 'utf-8' codec"));
        assert!(
            result
                .skipped
                .iter()
                .any(|s| s.path == "atomics/T1004/T1004.yaml"
                    && s.reason == "atomic test 0 is not a mapping")
        );
        assert_eq!(
            reason("atomics/T1004/T1004.yaml", Some("Not a uuid")),
            "auto_generated_guid \"1234\" is not a uuid"
        );
        assert_eq!(
            reason("atomics/T1004/T1004.yaml", Some("Nul \u{fffd} here")),
            "it holds a NUL character"
        );
        assert_eq!(
            reason("atomics/T1005/T1005.yaml", Some("Long")),
            "its technique is 33 characters, not 1 to 32"
        );
        assert_eq!(
            reason("atomics/T1006/T1006.yaml", None),
            "larger than 10485760 bytes"
        );

        // what one long line of a file gives each of its tests is kept short, and a skipped test's name
        // can't carry a terminal's escape codes
        let long = format!(
            "display_name: {}\natomic_tests:\n- name: Named\n  auto_generated_guid: {GUID_A}\n  \
             executor: {{name: {}}}\n- name: \"\\e[31mred\\r\\nline\"\n",
            "n".repeat(600),
            "e".repeat(100)
        );
        let result = parse_atomics(
            vec![file("atomics/T1003/T\u{1b}[2J1003.yaml", &long)],
            &CatalogLimits::default(),
        )
        .expect("parses");
        let entry = &result.entries[0];
        assert_eq!(
            entry.technique_name.as_deref().map(str::len),
            Some(MAX_NAME_CHARS)
        );
        assert_eq!(
            entry.executor.as_deref().map(str::len),
            Some(MAX_EXECUTOR_CHARS)
        );
        assert_eq!(
            result.skipped,
            [Skipped {
                path: "atomics/T1003/T\u{fffd}[2J1003.yaml".to_owned(),
                name: Some("\u{fffd}[31mred\u{fffd}\u{fffd}line".to_owned()),
                reason: "no auto_generated_guid".to_owned(),
            }]
        );
        assert_eq!(
            printable("git said \u{1b}]0;title\u{7}\r\n\tand more\u{9b}"),
            "git said \u{fffd}]0;title\u{fffd}\u{fffd}\n\tand more\u{fffd}"
        );

        // aliases that build more than a refresh may read fail the whole read, however small the files
        let aliased = format!(
            "long: &long {}\natomic_tests:\n{}",
            "x".repeat(2000),
            (0..10)
                .map(|i| format!(
                    "- name: Test {i}\n  auto_generated_guid: aaaaaaaa-1111-4111-8111-11111111111{i}\n  \
                     description: *long\n"
                ))
                .collect::<String>()
        );
        let small = CatalogLimits {
            max_total_bytes: 20_000,
            ..CatalogLimits::default()
        };
        assert!(aliased.len() < 4000);
        let error = parse_atomics(vec![file("atomics/T1003/T1003.yaml", &aliased)], &small)
            .expect_err("22,000 bytes of text built");
        assert!(
            error
                .0
                .contains("build more than 2000000 YAML nodes or 20000 bytes of text"),
            "{error}"
        );
        let built = parse_atomics(
            vec![file("atomics/T1003/T1003.yaml", &aliased)],
            &CatalogLimits::default(),
        )
        .expect("within the default");
        assert_eq!(built.entries.len(), 10);
        assert!(built.built_text_bytes > 22_000 && built.built_nodes > 40);

        // more tests than a commit may define fails the whole read
        let many: Vec<String> = (0..3)
            .map(|i| {
                test(
                    &format!("Test {i}"),
                    Some(&format!("aaaaaaaa-1111-4111-8111-11111111111{i}")),
                    "windows",
                    "sh",
                )
            })
            .collect();
        let error = parse_atomics(
            vec![file(
                "atomics/T1003/T1003.yaml",
                &atomic("T1003", "x", &many),
            )],
            &CatalogLimits {
                max_tests: 2,
                ..CatalogLimits::default()
            },
        )
        .expect_err("3 tests");
        assert!(error.0.contains("more than 2 tests"), "{error}");
    }

    /// A trial against a real repository, for whoever points the catalog at one: `ACE_RS_ART_REPOSITORY` is
    /// its path or URL and `ACE_RS_ART_BRANCH` its branch (master by default). It fetches it into a mirror of
    /// its own, reads it within the default limits, stores it in a test database twice, and prints what
    /// a refresh stores and skips, with how long each part took. With `ACE_RS_ART_REPORT`, it writes each
    /// test's guid, content hash, technique, platforms, executor and a hash of its name, description and
    /// technique's name there, one a line, to compare with ace3's `parse_atomics` over the same commit.
    /// Nothing of the repository is kept: the mirror is in a temporary directory, and the database goes
    /// with the test.
    #[tokio::test]
    #[ignore = "needs ACE_RS_ART_REPOSITORY, the path or URL of an Atomic Red Team repository"]
    async fn a_real_repository_parses() {
        let url = std::env::var("ACE_RS_ART_REPOSITORY").expect("ACE_RS_ART_REPOSITORY");
        let branch = std::env::var("ACE_RS_ART_BRANCH").unwrap_or_else(|_| "master".to_owned());
        let mirrors = tempfile::tempdir().expect("a directory");
        let section = SvsCatalogSection {
            repositories: BTreeMap::from([(
                "trial".to_owned(),
                SvsCatalogRepository {
                    url,
                    branch,
                    ssh_key: None,
                },
            )]),
            mirror_dir: Some(mirrors.path().to_path_buf()),
            ..SvsCatalogSection::default()
        };
        let config = CatalogConfig::from_section(&section).expect("valid settings");
        let started = std::time::Instant::now();
        let read = tokio::task::spawn_blocking(move || read_repository(&config, "trial", None))
            .await
            .expect("the read ends")
            .expect("reads the repository");
        let elapsed = started.elapsed();
        let parsed = read.parsed.expect("its tests");
        let files: BTreeSet<&str> = parsed.entries.iter().map(|e| e.path.as_str()).collect();
        let techniques: BTreeSet<&str> = parsed
            .entries
            .iter()
            .map(|e| e.technique.as_str())
            .collect();
        println!(
            "commit {}: {} tests in {} files, {} techniques, {} skipped, in {elapsed:?}",
            read.commit,
            parsed.entries.len(),
            files.len(),
            techniques.len(),
            parsed.skipped.len()
        );
        println!(
            "built {} YAML nodes and {} bytes of text",
            parsed.built_nodes, parsed.built_text_bytes
        );
        let mut by_reason: BTreeMap<String, usize> = BTreeMap::new();
        for skipped in &parsed.skipped {
            // a reason without what's particular to one test
            let reason = skipped.reason.split(['"', '\n']).next().unwrap_or_default();
            let reason = match reason.split_once("auto_generated_guid ") {
                Some((_, rest)) if rest.contains("is used by") => {
                    "auto_generated_guid is used by an earlier test"
                }
                _ => reason,
            };
            *by_reason.entry(reason.trim().to_owned()).or_default() += 1;
        }
        for (reason, count) in &by_reason {
            println!("skipped {count}: {reason}");
        }
        for skipped in parsed.skipped.iter().filter(|s| s.name.is_none()) {
            println!("skipped file {}: {}", skipped.path, skipped.reason);
        }
        let mut platforms: BTreeMap<&str, usize> = BTreeMap::new();
        let mut executors: BTreeMap<&str, usize> = BTreeMap::new();
        for entry in &parsed.entries {
            for platform in &entry.platforms {
                *platforms.entry(platform).or_default() += 1;
            }
            *executors
                .entry(entry.executor.as_deref().unwrap_or("(none)"))
                .or_default() += 1;
        }
        println!("platforms: {platforms:?}");
        println!("executors: {executors:?}");
        if let Ok(report) = std::env::var("ACE_RS_ART_REPORT") {
            let mut lines: Vec<String> = parsed
                .entries
                .iter()
                .map(|e| {
                    // its name, description and technique's name as one hash, so the line stays one line
                    let text = format!(
                        "{}\0{}\0{}",
                        e.name,
                        e.description.as_deref().unwrap_or_default(),
                        e.technique_name.as_deref().unwrap_or_default()
                    );
                    format!(
                        "{} {} {} {} {} {}",
                        e.guid,
                        e.content_hash,
                        e.technique,
                        e.platforms.join(","),
                        e.executor.as_deref().unwrap_or("-"),
                        hex::encode(Sha256::digest(text.as_bytes()))
                    )
                })
                .collect();
            lines.sort();
            std::fs::write(&report, lines.join("\n") + "\n").expect("writes the report");
        }

        // what the database makes of it: every test stored, and a second store of the same commit
        // changing none
        let test_db = crate::testing::TestDb::new().await;
        let mut conn = test_db.db().pool().acquire().await.expect("a connection");
        for (round, expected) in [(1, (parsed.entries.len() as i64, 0)), (2, (0, 0))] {
            let mut result = RefreshResult::default();
            let started = std::time::Instant::now();
            store(&mut conn, "trial", &read.commit, &parsed, &mut result)
                .await
                .expect("stores");
            println!(
                "store {round}: {} tests, {} added, {} changed, {} removed, {} skipped, in {:?}",
                result.tests,
                result.added,
                result.changed,
                result.removed,
                result.skipped.len(),
                started.elapsed()
            );
            assert_eq!((result.added, result.changed), expected);
            assert_eq!(result.tests, parsed.entries.len() as i64);
        }
        let statuses = repository_status(&mut conn, &CatalogConfig::default())
            .await
            .expect("reads");
        assert_eq!(statuses[0].test_count, parsed.entries.len() as i64);
    }

    #[test]
    fn a_url_is_shown_without_its_credentials() {
        for (url, shown) in [
            (
                "https://ghp_secret@git.example/org/art.git",
                "https://git.example/org/art.git",
            ),
            (
                "https://user:pass@git.example:8443/art.git",
                "https://git.example:8443/art.git",
            ),
            (
                "https://example.invalid/atomic-red-team.git",
                "https://example.invalid/atomic-red-team.git",
            ),
            (
                "ssh://git@forge.example/art.git",
                "ssh://forge.example/art.git",
            ),
            (
                "git@forge.example:org/art.git",
                "git@forge.example:org/art.git",
            ),
            ("/srv/git/art.git", "/srv/git/art.git"),
            (
                "https://git.example/a@b/art.git",
                "https://git.example/a@b/art.git",
            ),
        ] {
            assert_eq!(strip_url_credentials(url), shown, "{url}");
        }
    }

    #[test]
    fn platforms_become_slugs() {
        let platforms = ["windows", "iaas:aws", "iaas:gcp", "azure-ad", "linux"].map(str::to_owned);
        assert_eq!(
            platform_slugs(&platforms),
            ["iaas", "identity-provider", "linux", "windows"]
        );
    }
}
