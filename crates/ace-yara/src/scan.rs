//! Scanning bytes with a ruleset, the way `YaraScanner.scan` in yara_scanner_v2 3.0.0 scans
//! a file and filters its matches.

use std::fmt;
use std::time::Duration;

use serde::Serialize;

use crate::filter::{self, RuleFilter, Target};
use crate::load::Ruleset;
use crate::meta::Meta;

/// One scan: the bytes and what the filter and the externals need to know about the file.
#[derive(Debug, Clone, Copy)]
pub struct ScanRequest<'a> {
    pub data: &'a [u8],
    /// The file's path inside the alert. It sets the `filename`, `filepath` and `extension`
    /// externals and is what `file_name`, `full_path` and `file_ext` compare against.
    pub path: &'a str,
    /// The file's mime type, which `mime_type` compares against.
    pub mime_type: &'a str,
    /// The file's `yara_meta` tags, which `meta_tags` compares against.
    pub meta_tags: &'a [String],
    /// How long the scan may take. yara-x checks it about once a second.
    pub timeout: Duration,
}

/// One occurrence of a pattern.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct PatternMatch {
    /// The pattern's identifier, such as `$a`.
    pub identifier: String,
    pub offset: usize,
    pub length: usize,
}

/// A rule that matched.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Match {
    pub namespace: String,
    pub rule: String,
    pub meta: Meta,
    pub tags: Vec<String>,
    /// Every occurrence of every public pattern, pattern by pattern in the order the rule
    /// defines them, each pattern's in the order of their offsets, as yara-python lists them.
    pub patterns: Vec<PatternMatch>,
}

/// A scan's matches, split by the filter.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScanOutcome {
    /// The matches the filter kept: what ace3's `YaraScanner.scan_results` holds.
    pub matches: Vec<Match>,
    /// The matches the filter dropped, because a directive disagreed with the file or the
    /// rule is blacklisted. ace3 discards these; they are kept here for comparisons.
    pub dropped: Vec<Match>,
}

#[derive(Debug)]
pub enum ScanError {
    /// The scan ran past its timeout. A timeout is never an empty list of matches.
    Timeout,
    /// yara-x failed to scan.
    Failed(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Timeout => write!(f, "the scan timed out"),
            ScanError::Failed(e) => write!(f, "the scan failed: {e}"),
        }
    }
}

impl std::error::Error for ScanError {}

/// Scans with one ruleset. A scanner holds yara-x's per-scanner state, so reuse one for
/// many scans.
pub struct Scanner<'r> {
    ruleset: &'r Ruleset,
    inner: yara_x::Scanner<'r>,
}

impl<'r> Scanner<'r> {
    pub fn new(ruleset: &'r Ruleset) -> Self {
        Scanner {
            ruleset,
            inner: yara_x::Scanner::new(&ruleset.rules),
        }
    }

    pub fn scan(&mut self, request: &ScanRequest<'_>) -> Result<ScanOutcome, ScanError> {
        let target = Target {
            path: request.path,
            mime_type: request.mime_type,
            meta_tags: request.meta_tags,
        };

        for (name, value) in [
            ("filename", target.file_name()),
            ("filepath", target.path),
            ("extension", target.extension()),
            ("filetype", ""),
        ] {
            self.inner
                .set_global(name, value)
                .map_err(|e| ScanError::Failed(e.to_string()))?;
        }
        self.inner.set_timeout(request.timeout);

        let results = self.inner.scan(request.data).map_err(|e| match e {
            yara_x::ScanError::Timeout => ScanError::Timeout,
            other => ScanError::Failed(other.to_string()),
        })?;

        let mut outcome = ScanOutcome::default();
        let no_directives = RuleFilter::default();
        for rule in results.matching_rules() {
            let found = Match {
                namespace: rule.namespace().to_string(),
                rule: rule.identifier().to_string(),
                meta: Meta::from_yara_x(rule.metadata()),
                tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
                patterns: rule
                    .patterns()
                    .flat_map(|pattern| {
                        let identifier = pattern.identifier();
                        pattern.matches().map(move |m| PatternMatch {
                            identifier: identifier.to_string(),
                            offset: m.range().start,
                            length: m.range().len(),
                        })
                    })
                    .collect(),
            };

            // Every rule loaded through `load` has a filter; rules without one have no
            // directives to apply.
            let rule_filter = self
                .ruleset
                .filter(&found.namespace, &found.rule)
                .unwrap_or(&no_directives);
            if filter::keeps(&found.rule, rule_filter, &self.ruleset.blacklist, &target) {
                outcome.matches.push(found);
            } else {
                outcome.dropped.push(found);
            }
        }
        Ok(outcome)
    }
}
