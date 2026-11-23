//! YARA validation (PLAN.md 7.10 batch 3): ace3's `saq/svs/yara/`. A change to a rule repository is replayed
//! over every stored sample and compared against the samples' labels, so a pull request learns what it does
//! to the graded corpus before it merges. Validation warns; it never blocks.
//!
//! - `layout`: which directories of a commit the YARA pool loads.
//! - `repository`: SVS's own mirror of a repository, and the export of a commit's rules from it.
//! - `corpus`: the stored captures as units to scan, with their samples' labels, copied out of the bucket.
//! - `diff`: the two scans against the labels.
//! - `replay`: one validation from start to finish, its scans in a contained process.
//!
//! `crate::svs::validations` holds the queue a request waits in and the workers of `ace serve` that run it.
//!
//! **Bounds.** A validation's work is held three ways. Its time: fetching and exporting by
//! `fetch_timeout_seconds`, each commit's compile and scan by `scan_timeout_seconds`, which the contained
//! process's CPU-time limit and its supervisor's kill both enforce, and the whole run by its lease, which a
//! worker that stops heartbeating loses. Its size: the export by `max_archive_bytes` and
//! `max_archive_members` (unset by default, as in ace3), the corpus by `max_corpus_files` and
//! `max_corpus_bytes`, which fail the validation rather than report on part of it, and the scan's memory
//! by `scan_memory_mb`. And how many at once: `max_concurrent_validations` workers per `ace serve`.

pub mod corpus;
pub mod diff;
pub mod layout;
pub mod replay;
pub mod repository;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ace_sdk::{Secret, Secrets, SvsRepository, SvsYaraSection};

use self::corpus::CorpusLimits;
use self::layout::RepoLayout;

/// YARA validation's settings, from the overlay's `svs.yara` (`ace_sdk::SvsYaraSection`), checked.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationConfig {
    pub repositories: BTreeMap<String, SvsRepository>,
    /// Each repository's SSH private key, by the repository's name, for those whose `ssh_key` names a
    /// secret that was resolved (`with_secrets`). Its `Debug` output hides the keys.
    pub ssh_keys: BTreeMap<String, Secret>,
    pub scan_timeout: Duration,
    pub max_concurrent_validations: usize,
    pub fetch_timeout: Duration,
    pub max_archive_bytes: Option<u64>,
    pub max_archive_members: Option<u64>,
    pub corpus_limits: CorpusLimits,
    pub scan_memory_mb: u64,
    pub file_timeout: Duration,
    pub mirror_dir: PathBuf,
    pub work_dir: PathBuf,
    pub retention_days: u32,
    pub prune_batch_size: u32,
    pub poll_interval: Duration,
    pub heartbeat_interval: Duration,
    pub lease: Duration,
    pub max_attempts: u32,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        ValidationConfig::from_section(&SvsYaraSection::default()).expect("the defaults are valid")
    }
}

impl ValidationConfig {
    /// The settings `section` gives, or why they can't run.
    pub fn from_section(section: &SvsYaraSection) -> Result<ValidationConfig, String> {
        section.check()?;
        let temp = std::env::temp_dir().join("ace-rs-svs");
        let work_dir = section
            .work_dir
            .clone()
            .unwrap_or_else(|| temp.join("work"));
        check_work_root(&work_dir)?;
        Ok(ValidationConfig {
            repositories: section.repositories.clone(),
            ssh_keys: BTreeMap::new(),
            scan_timeout: Duration::from_secs(section.scan_timeout_seconds),
            max_concurrent_validations: section.max_concurrent_validations as usize,
            fetch_timeout: Duration::from_secs(section.fetch_timeout_seconds),
            max_archive_bytes: section.max_archive_bytes,
            max_archive_members: section.max_archive_members,
            corpus_limits: CorpusLimits {
                max_files: section.max_corpus_files,
                max_bytes: section.max_corpus_bytes,
            },
            scan_memory_mb: section.scan_memory_mb,
            file_timeout: Duration::from_secs(section.file_timeout_seconds),
            mirror_dir: section
                .mirror_dir
                .clone()
                .unwrap_or_else(|| temp.join("mirrors")),
            work_dir,
            retention_days: section.retention_days,
            prune_batch_size: section.prune_batch_size,
            poll_interval: Duration::from_secs_f64(section.poll_interval_seconds),
            heartbeat_interval: Duration::from_secs(section.heartbeat_interval_seconds),
            lease: Duration::from_secs(section.lease_seconds),
            max_attempts: section.max_attempts,
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

    /// The settings with each repository's SSH key taken from `secrets` by the name its `ssh_key` gives. A
    /// name that wasn't resolved leaves the repository without its key, and its fetch refuses to run
    /// (`ssh_key`).
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

    /// The layout of a repository in `repositories`: ace3's `resolve_layout`.
    pub fn layout(&self, repository: &str) -> Result<RepoLayout, String> {
        match self.repositories.get(repository) {
            Some(config) => Ok(RepoLayout::new(repository, &config.signature_dir)),
            None => Err(format!(
                "repository {repository} is not in svs.yara.repositories"
            )),
        }
    }
}

/// Refuses a work directory with a `.` in its path: YARA's `extension` external and the `file_ext` filter
/// take everything after the last `.` of the whole path, so a `.` above a sample changes them for a file
/// name without one. ace3's `_check_work_root`.
pub fn check_work_root(root: &Path) -> Result<(), String> {
    let resolved = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    if resolved.to_string_lossy().contains('.') || root.to_string_lossy().contains('.') {
        return Err(format!(
            "svs.yara.work_dir ({}) has a '.' in its path",
            root.display()
        ));
    }
    if !root.is_absolute() {
        return Err(format!(
            "svs.yara.work_dir ({}) must be an absolute path",
            root.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A repository's SSH key is the secret its `ssh_key` names. One that isn't set is an error naming the
    /// secret, so its fetch never runs without the key; a repository naming none has none.
    #[test]
    fn a_repository_s_ssh_key_is_its_secret() {
        let section = ace_sdk::Overlay::from_yaml(
            "secrets: {rules_key: env:RULES_KEY, unset_key: env:UNSET_KEY}\n\
             svs: {yara: {repositories: {\n\
               keyed: {url: /x, branch: main, ssh_key: rules_key},\n\
               unset: {url: /y, branch: main, ssh_key: unset_key},\n\
               plain: {url: /z, branch: main}}}}\n",
        )
        .expect("parses")
        .svs
        .yara;
        let config = ValidationConfig::from_section(&section).expect("valid settings");
        assert_eq!(config.secret_names(), ["rules_key", "unset_key"]);
        assert!(config.ssh_keys.is_empty());
        // before the secrets are read, a keyed repository has no key and says so
        assert!(config.ssh_key("keyed").is_err());
        let secrets = Secrets::new()
            .with("rules_key", Secret::new("the key's text"))
            .with("another", Secret::new("not asked for"));
        let config = config.with_secrets(&secrets);
        assert_eq!(
            config
                .ssh_key("keyed")
                .expect("set")
                .map(|k| k.expose().to_owned()),
            Some("the key's text".to_owned())
        );
        assert_eq!(
            config.ssh_key("unset").expect_err("not set"),
            "repository unset: its ssh_key, the secret unset_key, isn't set"
        );
        assert_eq!(config.ssh_key("plain"), Ok(None));
        assert_eq!(config.ssh_key("nowhere"), Ok(None));
        assert_eq!(config.ssh_keys.len(), 1, "only what a repository names");
        assert!(!format!("{config:?}").contains("the key's text"));
    }

    /// test_layout.py's `test_only_configured_repositories_resolve`: a repository named in the overlay
    /// resolves to its signature directory, and one that isn't is refused. ace3's second refusal, a name with
    /// no `git_repo_*` section, has no counterpart: the overlay's entry is the repository's whole setting.
    #[test]
    fn only_configured_repositories_resolve() {
        let section = ace_sdk::Overlay::from_yaml(
            "svs: {yara: {repositories: {svs_rules: {url: /x, branch: main}}}}",
        )
        .expect("parses")
        .svs
        .yara;
        let config = ValidationConfig::from_section(&section).expect("valid");
        assert_eq!(
            config.layout("svs_rules").expect("resolves").signature_dir,
            "yara"
        );
        let error = config.layout("nope").expect_err("refused");
        assert!(error.contains("not in svs.yara.repositories"), "{error}");
        assert!(ValidationConfig::default().layout("svs_rules").is_err());
    }

    /// test_config.py's `test_a_work_dir_with_a_dot_is_refused`.
    #[test]
    fn a_work_dir_with_a_dot_is_refused() {
        let tmp = tempfile::Builder::new()
            .prefix("svs")
            .tempdir_in("/tmp")
            .expect("a directory");
        check_work_root(&tmp.path().join("svs").join("work")).expect("no dot");
        let error = check_work_root(&tmp.path().join("svs.d").join("work")).expect_err("a dot");
        assert!(error.contains("has a '.' in its path"), "{error}");
    }
}
