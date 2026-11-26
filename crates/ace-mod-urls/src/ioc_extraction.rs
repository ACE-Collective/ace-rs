//! `ioc_extraction`: ace3's `IOCExtractionAnalyzer` (`saq/modules/file_analysis/ioc_extraction.py`).
//!
//! For a file with the `extract_iocs` directive: its text, the visible text if it's HTML (bs4's
//! `get_text()` on lxml, `ace_lxml::soup`), re-fanged by the configured patterns until nothing
//! changes, then its URLs (urlfinderlib, `ace-urlfinder`) and the configured patterns' matches,
//! less those an ignore pattern matches, added as observables with the configured directives,
//! tags and display type, each `extracted_from` the file. If re-fanging changed the text, the
//! text is added too, as `<file>.refanged.txt` (`type=document.text.refanged`).
//!
//! Where ace-rs departs:
//!
//! - The configuration is the module's overlay settings, with ace3's `etc/ioc_extraction.yaml` as
//!   the default, where ace3 reads that file and reloads it when it changes (PLAN.md 5.14 leaves
//!   the choice to this port). `refang_patterns` is a list of `{replacement, patterns}` rather than
//!   a mapping, so its order is explicit.
//! - Patterns are Python `re` on fancy-regex (`crate::pyre`).
//! - urlfinderlib's URLs come as a set, whose order changes with Python's hash seed; here they're
//!   sorted, so `iocs.url` is in the same order each time.
//! - A type ace-rs doesn't know, such as the default configuration's `cve`, is in the details but
//!   makes no observable: ace3 makes a `DefaultObservable` of any type, and ace-rs's types are fixed
//!   when the binary is built (ace3 #1030). The re-fanged file's display type isn't kept, as a
//!   file record has none; the alert view names it by its path.
//! - Observables aren't volatile, as `url_extraction`'s aren't.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::time::Duration;

use crate::pyre::Pattern;
use ace_pycompat::pystr;
use ace_results::FileRole;
use ace_results::types::ioc_extraction::IocExtractionAnalysis;
use ace_results::{AnalysisType, ObservableKind, Relationship, RelationshipKind, ResultEnvelope};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use ace_urlfinder::{Finder, magic};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::pyre;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<IocExtraction>();

const DIRECTIVE_EXTRACT_IOCS: &str = "extract_iocs";

/// One re-fang rule: what each pattern's matches become.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Refang {
    pub replacement: String,
    pub patterns: Vec<String>,
}

fn default_display_type() -> Option<String> {
    Some("IOC".to_owned())
}

/// ace3's `BaseConfig`: what an extracted observable gets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UrlConfig {
    #[serde(default)]
    pub directives: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub volatile: bool,
    #[serde(default)]
    pub ignored_patterns: Vec<String>,
    #[serde(default = "default_display_type")]
    pub display_type: Option<String>,
}

impl Default for UrlConfig {
    fn default() -> Self {
        UrlConfig {
            directives: Vec::new(),
            tags: Vec::new(),
            volatile: false,
            ignored_patterns: Vec::new(),
            display_type: default_display_type(),
        }
    }
}

/// ace3's `PatternConfig`: a pattern and the observable type its matches are.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatternConfig {
    pub pattern: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub directives: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub volatile: bool,
    #[serde(default)]
    pub ignored_patterns: Vec<String>,
    #[serde(default = "default_display_type")]
    pub display_type: Option<String>,
}

/// The module's settings: ace3's section and its YAML file in one.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct IocExtractionSettings {
    /// The largest file to read, in megabytes.
    pub max_file_size: u64,
    pub refang_patterns: Vec<Refang>,
    pub patterns: Vec<PatternConfig>,
    /// What URLs get; without it no URLs are extracted.
    pub urls: Option<UrlConfig>,
}

fn pattern(pattern: &str, kind: &str, ignored: &[&str]) -> PatternConfig {
    PatternConfig {
        pattern: pattern.to_owned(),
        kind: kind.to_owned(),
        directives: Vec::new(),
        tags: Vec::new(),
        volatile: false,
        ignored_patterns: ignored.iter().map(|p| (*p).to_owned()).collect(),
        display_type: default_display_type(),
    }
}

const MIXED_CASE: &str = "(?=.*[a-f])(?=.*[A-F])";

impl Default for IocExtractionSettings {
    /// ace3's `etc/ioc_extraction.yaml`.
    fn default() -> Self {
        let refang = |replacement: &str, patterns: &[&str]| Refang {
            replacement: replacement.to_owned(),
            patterns: patterns.iter().map(|p| (*p).to_owned()).collect(),
        };
        IocExtractionSettings {
            max_file_size: 10,
            refang_patterns: vec![
                refang("http", &["(?i)hxxp"]),
                refang(":", &[r"[\[\(]\s*:\s*[\]\)]"]),
                refang("://", &[r"[\[\(]\s*:\//\s*[\]\)]"]),
                refang(".", &[r"[\[\(]\s*\.\s*[\]\)]", r"\s+dot\s+"]),
                refang("@", &[r"[\[\(]\s*(?:@|at)\s*[\]\)]"]),
            ],
            patterns: vec![
                pattern(
                    r"\b(?<!\d\.)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?!\.\d)\b",
                    "ip",
                    &[],
                ),
                pattern(
                    r"(?i)(?<![:\w])(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|:(?::[0-9a-f]{1,4}){1,7}|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}|::)(?![:\w])",
                    "ip",
                    &[MIXED_CASE],
                ),
                pattern(r"(?i)\b[0-9a-f]{32}\b", "md5", &[MIXED_CASE]),
                pattern(r"(?i)\b[0-9a-f]{40}\b", "sha1", &[MIXED_CASE]),
                pattern(r"(?i)\b[0-9a-f]{64}\b", "sha256", &[MIXED_CASE]),
                pattern(
                    r"(?<![<.;!#$%&'*+/=?^`{|}~-])\b[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
                    "email_address",
                    &[],
                ),
                pattern(
                    r"<[a-zA-Z0-9;!#$%&'*+\-/=?^_`{|}~]+(?:\.[a-zA-Z0-9;!#$%&'*+\-/=?^_`{|}~]+)*@[a-zA-Z0-9;!#$%&'*+\-/=?^_`{|}~]+(?:\.[a-zA-Z0-9;!#$%&'*+\-/=?^_`{|}~]+)*>",
                    "message_id",
                    &[],
                ),
                pattern(r"(?i)\bCVE-\d{4}-\d{4,}\b", "cve", &[]),
            ],
            urls: Some(UrlConfig::default()),
        }
    }
}

struct Compiled {
    /// Index into the settings' patterns.
    config: usize,
    regex: Pattern,
    ignored: Vec<(String, Pattern)>,
}

/// The module: its patterns compiled, invalid ones left out as ace3 logs and skips them, and
/// libmagic's database, mapped before containment, which can't open it, and loaded only by a task
/// that looks for URLs.
pub struct IocExtraction {
    refang: Vec<(String, Vec<Pattern>)>,
    patterns: Vec<Compiled>,
    url_ignored: Vec<(String, Pattern)>,
    database: magic::Database,
}

impl IocExtraction {
    /// The module with libmagic's database at `path` in place of `init`'s.
    pub fn with_database(self, path: &Path) -> IocExtraction {
        IocExtraction {
            database: magic::Database::open(path),
            ..self
        }
    }
}

fn compile_logged(pattern: &str, what: &str) -> Option<Pattern> {
    match pyre::compile(pattern) {
        Ok(regex) => Some(regex),
        Err(e) => {
            tracing::error!("invalid {what} regex {pattern:?}: {e}");
            None
        }
    }
}

impl Module for IocExtraction {
    const NAME: &'static str = IocExtractionAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const REQUIRED_DIRECTIVES: &'static [&'static str] = &[DIRECTIVE_EXTRACT_IOCS];
    // ace3 gives it the global maximum_analysis_time
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        memory_mb: 2048,
        cpu_seconds: 60,
    };
    type Output = IocExtractionAnalysis;
    type Settings = IocExtractionSettings;

    fn init(settings: &IocExtractionSettings) -> Result<Self, ModuleError> {
        let refang = settings
            .refang_patterns
            .iter()
            .map(|rule| {
                let patterns = rule
                    .patterns
                    .iter()
                    .filter_map(|p| compile_logged(p, "refang"))
                    .collect();
                (rule.replacement.clone(), patterns)
            })
            .collect();
        let ignored = |patterns: &[String]| -> Vec<(String, Pattern)> {
            patterns
                .iter()
                .filter_map(|p| compile_logged(p, "ignore").map(|r| (p.clone(), r)))
                .collect()
        };
        let patterns = settings
            .patterns
            .iter()
            .enumerate()
            .filter_map(|(config, p)| {
                compile_logged(&p.pattern, "pattern").map(|regex| Compiled {
                    config,
                    regex,
                    ignored: ignored(&p.ignored_patterns),
                })
            })
            .collect();
        let url_ignored = settings
            .urls
            .as_ref()
            .map(|u| ignored(&u.ignored_patterns))
            .unwrap_or_default();
        Ok(IocExtraction {
            refang,
            patterns,
            url_ignored,
            database: magic::Database::open(Path::new(magic::DATABASE)),
        })
    }
}

/// `open(path, "r", errors="ignore").read()` in ace3's UTF-8 mode: invalid bytes dropped, and
/// `\r\n` and a lone `\r` read as `\n`.
pub fn read_text(bytes: &[u8]) -> String {
    let text = pystr::decode_utf8_ignore(bytes);
    if !text.contains('\r') {
        return text.into_owned();
    }
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// `_is_excluded`: the first ignore pattern that matches.
fn excluded<'p>(value: &str, ignored: &'p [(String, Pattern)]) -> Option<&'p str> {
    let plain = pyre::classes_agree(value);
    ignored
        .iter()
        .find(|(_, regex)| regex.for_text(plain).is_match(value).unwrap_or(false))
        .map(|(pattern, _)| pattern.as_str())
}

/// `pattern.subn(repl, text)`. fancy-regex's error, such as its backtracking limit, fails the task
/// rather than replace part of the text.
fn subn(
    regex: &fancy_regex::Regex,
    repl: &str,
    text: &str,
) -> Result<(String, usize), ModuleError> {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    let mut count = 0;
    for caps in regex.captures_iter(text) {
        let caps = caps.map_err(|e| ModuleError::other(format!("refang regex: {e}")))?;
        let Some(m) = caps.get(0) else {
            continue;
        };
        out.push_str(&text[last..m.start()]);
        out.push_str(&pyre::expand(repl, &caps));
        last = m.end();
        count += 1;
    }
    out.push_str(&text[last..]);
    Ok((out, count))
}

/// What one observable to add gets: the settings of the pattern or the URL config that found it.
#[derive(Clone)]
struct Extras {
    directives: Vec<String>,
    tags: Vec<String>,
    display_type: Option<String>,
}

impl Parser for IocExtraction {
    fn analyze(
        &self,
        ctx: &TaskContext<IocExtractionSettings>,
    ) -> Result<Outcome<IocExtractionAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let settings = ctx.settings();
        if file.size == 0 {
            return Ok(Outcome::Skipped("an empty file".to_owned()));
        }
        if file.size > settings.max_file_size * 1024 * 1024 {
            return Ok(Outcome::Skipped("too large for IOC extraction".to_owned()));
        }
        let raw = read_text(&fs::read(&file.local_path)?);
        let original = ace_lxml::soup::get_text(&raw).unwrap_or_else(|| raw.clone());
        ctx.check_cancelled()?;

        // re-fang until nothing changes
        let mut text = original.clone();
        let mut changed = true;
        while changed {
            ctx.check_cancelled()?;
            changed = false;
            for (replacement, patterns) in &self.refang {
                for regex in patterns {
                    let plain = pyre::classes_agree(&text);
                    let (new_text, count) = subn(regex.for_text(plain), replacement, &text)?;
                    if count > 0 {
                        changed = true;
                        text = new_text;
                    }
                }
            }
        }

        let mut ignored: BTreeSet<[String; 3]> = BTreeSet::new();
        let mut to_add: Vec<((String, String), Extras)> = Vec::new();
        let mut add = |key: (String, String), extras: Extras| match to_add
            .iter_mut()
            .find(|(k, _)| *k == key)
        {
            Some(slot) => slot.1 = extras,
            None => to_add.push((key, extras)),
        };

        if let Some(url_config) = &settings.urls {
            // the text is the file's after markup is stripped and IOCs re-fanged, which the type
            // step never described, so urlfinderlib asks libmagic, as ace3's does
            let load_magic = || self.database.load();
            let finder = Finder::on_demand(&load_magic);
            let urls =
                finder
                    .find_urls(text.as_bytes(), "", "", false)
                    .map_err(|e| match finder.load_error() {
                        Some(why) => ModuleError::other(why.to_owned()),
                        None => ModuleError::other(format!("find_urls raised {e}")),
                    })?;
            let extras = Extras {
                directives: url_config.directives.clone(),
                tags: url_config.tags.clone(),
                display_type: url_config.display_type.clone(),
            };
            for url in urls {
                if let Some(pattern) = excluded(&url, &self.url_ignored) {
                    ignored.insert(["url".to_owned(), url, pattern.to_owned()]);
                    continue;
                }
                add(("url".to_owned(), url), extras.clone());
            }
        }

        for compiled in &self.patterns {
            ctx.check_cancelled()?;
            let config = &settings.patterns[compiled.config];
            let extras = Extras {
                directives: config.directives.clone(),
                tags: config.tags.clone(),
                display_type: config.display_type.clone(),
            };
            let regex = compiled.regex.for_text(pyre::classes_agree(&text));
            let groups = regex.captures_len() > 1;
            for caps in regex.captures_iter(&text) {
                let caps = caps.map_err(|e| ModuleError::other(format!("regex: {e}")))?;
                let value = if groups { caps.get(1) } else { caps.get(0) };
                let Some(value) = value.map(|m| m.as_str().to_owned()) else {
                    return Err(ModuleError::other(
                        "TypeError: a pattern's first group didn't match",
                    ));
                };
                if let Some(pattern) = excluded(&value, &compiled.ignored) {
                    ignored.insert([config.kind.clone(), value, pattern.to_owned()]);
                    continue;
                }
                add((config.kind.clone(), value), extras.clone());
            }
        }

        let mut files = Vec::new();
        if text != original {
            let path = format!("{}.refanged.txt", file.path.as_str());
            let mut new_file =
                ctx.write_file(&path, text.as_bytes(), FileRole::DOCUMENT_TEXT_REFANGED)?;
            new_file.relationships.push(Relationship::new(
                RelationshipKind::ExtractedFrom,
                file_ref(file),
            ));
            files.push(new_file);
        }

        let mut iocs: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut observables = Vec::new();
        for ((kind, value), extras) in &to_add {
            iocs.entry(kind.clone()).or_default().push(value.clone());
            let Ok(observable_kind) = kind.parse::<ObservableKind>() else {
                tracing::warn!("ioc type {kind:?} isn't an observable type ace-rs knows");
                continue;
            };
            // what ace3's class of the type refuses isn't added
            let Some(mut observable) = ace_sdk::observable_rules::new(observable_kind, value)
            else {
                continue;
            };
            observable.relationships.push(Relationship::new(
                RelationshipKind::ExtractedFrom,
                file_ref(file),
            ));
            for directive in &extras.directives {
                if !observable.directives.contains(directive) {
                    observable.directives.push(directive.clone());
                }
            }
            for tag in &extras.tags {
                if !observable.tags.contains(tag) {
                    observable.tags.push(tag.clone());
                }
            }
            observable.display_type = extras.display_type.clone().filter(|d| !d.is_empty());
            observables.push(observable);
        }
        let total = to_add.len() as u64;
        let mut result = ResultEnvelope::new(IocExtractionAnalysis {
            iocs: iocs.clone(),
            total_count: total,
            ignored: ignored.into_iter().collect(),
        });
        result.summary = (total > 0).then(|| {
            // in the order the types were first found, as ace3's dict has them
            let mut kinds: Vec<&str> = Vec::new();
            for ((kind, _), _) in &to_add {
                if !kinds.contains(&kind.as_str()) {
                    kinds.push(kind);
                }
            }
            let counts: Vec<String> = kinds
                .iter()
                .map(|kind| format!("{kind}: {}", iocs[*kind].len()))
                .collect();
            format!("Extracted {total} IOCs ({})", counts.join(", "))
        });
        result.observables = observables;
        result.files = files;
        Ok(Outcome::Done(result))
    }
}

fn file_ref(file: &ace_sdk::InputFile) -> ace_results::ObservableRef {
    ace_results::ObservableRef::new(ObservableKind::File, file.sha256.to_hex())
}
