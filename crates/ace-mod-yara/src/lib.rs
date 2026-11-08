//! The YARA module, a port of ace3's `YaraScanner_v3_4` (`saq/modules/file_analysis/yara.py:171`)
//! onto `ace-yara`.
//!
//! It scans a file with a ruleset and keeps the matches ace3's filter keeps: the file's
//! `yara_meta` tags go to the `meta_tags` directive, its path to `file_name` and `full_path`, its
//! mime type to `mime_type`. Each rule that matched becomes a `yara_rule` observable, with its
//! uuid as a `signature_id` and each pattern as a `yara_string`. A match from a rule that may
//! alert (no `no_alert` or `qa` modifier) is a detection on the file and sandboxes it, or the
//! document it redirects to; `directive=` modifiers add directives and rule tags tag the file.
//!
//! In a YARA pool the module loads the ruleset the core built, from the pool's ruleset
//! directory (`rulesets`, PLAN.md 2.26), and every match records that ruleset's key and commit.
//! Without one, as in tests and `ace task replay` on a laptop, it compiles `signature_dir` when it
//! starts, and its matches record neither.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use ace_results::types::yara::{MatchContext, ScanResult, YaraScanResults};
use ace_results::{Bytes, Detection, NewObservable, ObservableKind, ResultEnvelope};
use ace_sdk::generation::{self, GenerationInfo};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use ace_yara::mime::{DEFAULT_DATABASE, MimeTyper};
use ace_yara::{LoadOptions, Ruleset, ScanError, ScanRequest, Scanner};
use regex::Regex;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<YaraScanner>();

/// ace3's built-in signature for a match of a rule without a `uuid` meta.
pub const YARA_RULE_MATCH: &str = "3557435e-da7f-4b1b-a5dd-655107839530";
/// The signature version of a rule that didn't come from a git repository.
pub const SIGNATURE_VERSION_UNKNOWN: &str = "unknown";

pub const DIRECTIVE_NO_SCAN: &str = "no_scan";
pub const DIRECTIVE_SANDBOX: &str = "sandbox";

/// The YARA module's settings: ace3's `analysis_module_yara_scanner_v3_4` section and the
/// scanner settings of its `service_yara` section.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct YaraSettings {
    /// The signature directory: one namespace per subdirectory. Compiled when `rulesets` isn't
    /// set.
    pub signature_dir: PathBuf,
    /// A YARA pool's ruleset directory, which the pool keeps on the core's current ruleset
    /// (`ace_sdk::generation`). The module loads the generation that is current when it starts.
    pub rulesets: Option<PathBuf>,
    /// Rule names whose matches are dropped.
    pub blacklist: Vec<String>,
    /// How many bytes of context to keep on each side of a pattern match.
    pub context_bytes: u64,
    /// How long a scan may take.
    pub timeout_seconds: u64,
}

impl Default for YaraSettings {
    fn default() -> Self {
        // ace3's saq.default.yaml
        YaraSettings {
            signature_dir: PathBuf::from("signatures/yara"),
            rulesets: None,
            blacklist: Vec::new(),
            context_bytes: 64,
            timeout_seconds: 10,
        }
    }
}

/// The YARA module, with its ruleset.
pub struct YaraScanner {
    /// None in a pool whose first ruleset hasn't arrived: the supervisor builds its modules
    /// before it has one, and runs no task until it does.
    ruleset: Option<Loaded>,
}

/// A ruleset and where it came from.
struct Loaded {
    ruleset: Ruleset,
    /// The key and commit of a ruleset the core built.
    built: Option<GenerationInfo>,
}

/// Loads a serialized ruleset as the module will, for a pool to check one before it switches
/// to it.
pub fn check_ruleset(path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    Ruleset::from_bytes(&bytes, &LoadOptions::default()).map(drop)
}

impl Module for YaraScanner {
    const NAME: &'static str = "yara_scanner_v3_4";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    /// ace3's YARA module skips a file with `no_scan` itself (`yara.py:299`); here the core
    /// doesn't queue it, and the SDK skips a run if the directive came later.
    const SKIP_DIRECTIVES: &'static [&'static str] = &[DIRECTIVE_NO_SCAN];
    const RESOURCES: Resources = Resources {
        memory_mb: 4096,
        ..Resources::DEFAULT
    };
    type Output = YaraScanResults;
    type Settings = YaraSettings;

    fn init(settings: &YaraSettings) -> Result<Self, ModuleError> {
        let options = LoadOptions {
            blacklist: settings.blacklist.iter().cloned().collect(),
        };
        if let Some(dir) = &settings.rulesets {
            let Some(current) = generation::current(dir)
                .map_err(|e| ModuleError::other(format!("the ruleset directory: {e}")))?
            else {
                return Ok(YaraScanner { ruleset: None });
            };
            let bytes = std::fs::read(current.data())
                .map_err(|e| ModuleError::other(format!("reading the ruleset: {e}")))?;
            let ruleset = Ruleset::from_bytes(&bytes, &options).map_err(|e| {
                ModuleError::other(format!("loading ruleset {}: {e}", current.info.key))
            })?;
            return Ok(YaraScanner {
                ruleset: Some(Loaded {
                    ruleset,
                    built: Some(current.info),
                }),
            });
        }
        let loaded = ace_yara::load_dir(&settings.signature_dir, &options)
            .map_err(|e| ModuleError::other(format!("loading the YARA rules: {e}")))?;
        for left_out in loaded.left_out() {
            tracing::error!(path = %left_out.path.display(), "a YARA rule file was left out");
        }
        Ok(YaraScanner {
            ruleset: Some(Loaded {
                ruleset: loaded.ruleset,
                built: None,
            }),
        })
    }
}

static SIP_STRING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\$sip_([0-9]+)$").expect("valid regex"));

/// `hexdump -C`, as ace3's `saq.util.ui.hexdump` writes it.
pub fn hexdump(data: &[u8]) -> String {
    let mut out = String::new();
    let mut previous: Option<&[u8]> = None;
    let mut squeezing = false;
    let mut offset = 0usize;
    for chunk in data.chunks(16) {
        if previous == Some(chunk) {
            if !squeezing {
                out.push_str("*\n");
                squeezing = true;
            }
        } else {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x} ")).collect();
            let area = format!(
                "{} {}",
                hex.iter().take(8).cloned().collect::<String>(),
                hex.iter().skip(8).cloned().collect::<String>()
            );
            let printable: String = chunk
                .iter()
                .map(|&b| {
                    if (0x20..0x7f).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            out.push_str(&format!("{offset:08x}  {area:<49} |{printable}|\n"));
            squeezing = false;
        }
        previous = Some(chunk);
        offset += chunk.len();
    }
    if offset > 0 {
        out.push_str(&format!("{offset:08x}\n"));
    }
    out
}

impl Parser for YaraScanner {
    fn analyze(
        &self,
        ctx: &TaskContext<YaraSettings>,
    ) -> Result<Outcome<YaraScanResults>, ModuleError> {
        let settings = ctx.settings();
        let Some(loaded) = &self.ruleset else {
            return Err(ModuleError::other(
                "no ruleset has arrived from the core yet",
            ));
        };
        let (key, commit) = match &loaded.built {
            Some(info) => (Some(info.key.clone()), Some(info.commit.clone())),
            None => (None, None),
        };
        let observable = ctx.observable();
        let file = ctx.input_file()?;
        if file.size == 0 {
            return Ok(Outcome::Skipped("an empty file".to_owned()));
        }
        let data = std::fs::read(&file.local_path)?;
        let mime_type = match &file.mime_type {
            Some(mime) => mime.clone(),
            // the core stores libmagic's answer with each file; one without it gets it here
            None => MimeTyper::open(std::path::Path::new(DEFAULT_DATABASE))
                .and_then(|typer| typer.mime_type(&data))
                .map_err(ModuleError::other)?,
        };
        let meta_tags: Vec<String> = file.yara_meta.iter().map(|t| t.to_string()).collect();
        ctx.check_cancelled()?;

        let mut scanner = Scanner::new(&loaded.ruleset);
        let outcome = match scanner.scan(&ScanRequest {
            data: &data,
            path: file.path.as_str(),
            mime_type: &mime_type,
            meta_tags: &meta_tags,
            // contained, a scan runs without yara-x's timeout, whose heartbeat is a thread;
            // the task's CPU-time limit and deadline bound it
            timeout: (!ctx.is_contained()).then(|| Duration::from_secs(settings.timeout_seconds)),
        }) {
            Ok(outcome) => outcome,
            // ace3 logs a timeout and moves on with no analysis
            Err(ScanError::Timeout) => {
                tracing::warn!("the YARA scan timed out");
                return Ok(Outcome::Skipped("the scan timed out".to_owned()));
            }
            Err(e) => return Err(ModuleError::other(e)),
        };
        // a rule an analyst disabled in place matches as if it hadn't
        let matches: Vec<_> = outcome
            .matches
            .into_iter()
            .filter(|m| m.meta.enabled())
            .collect();
        if matches.is_empty() {
            return Ok(Outcome::Skipped("no rule matched".to_owned()));
        }

        let mut result = ResultEnvelope::new(YaraScanResults::default());
        let mut alertable = false;
        let mut no_alert_rules: Vec<&str> = Vec::new();
        for m in &matches {
            let modifiers = m.meta.modifiers();
            if modifiers.is_empty() {
                alertable = true;
                continue;
            }
            let qa = modifiers
                .iter()
                .any(|x| x == ace_yara::rule_meta::MODIFIER_QA);
            let no_alert = qa
                || modifiers
                    .iter()
                    .any(|x| x == ace_yara::rule_meta::MODIFIER_NO_ALERT);
            if qa {
                tracing::info!(rule = %m.rule, "a YARA rule matched in QA mode");
            }
            if no_alert {
                no_alert_rules.push(&m.rule);
            } else {
                alertable = true;
            }
            // a rule in QA mode adds no directives
            if !qa {
                for modifier in &modifiers {
                    if modifier.starts_with("directive")
                        && let Some((_, directive)) = modifier.split_once('=')
                    {
                        result.analyzed.add_directive(directive);
                    }
                }
            }
        }
        if alertable {
            // a part of a decomposed file sandboxes the file it came from
            if observable.redirection.is_some() {
                result.redirected.add_directive(DIRECTIVE_SANDBOX);
            } else {
                result.analyzed.add_directive(DIRECTIVE_SANDBOX);
            }
        }

        let mut signature_ids: Vec<String> = Vec::new();
        let context_bytes = settings.context_bytes as usize;
        for m in &matches {
            push_observable(&mut result.observables, ObservableKind::YaraRule, &m.rule);
            let uuid = m.meta.uuid().filter(|u| !u.is_empty());
            if let Some(uuid) = &uuid
                && !signature_ids.contains(uuid)
            {
                push_observable(&mut result.observables, ObservableKind::SignatureId, uuid);
                signature_ids.push(uuid.clone());
            }
            for pattern in &m.patterns {
                push_observable(
                    &mut result.observables,
                    ObservableKind::YaraString,
                    &format!("{}:{}", m.rule, pattern.identifier),
                );
            }
            // the database lookups of $obsd_ strings come on the ruleset, which 7.6 builds
            // (crates/ace-core/src/reads.md); $obs_ strings aren't served

            if !no_alert_rules.contains(&m.rule.as_str()) {
                let mut detection =
                    Detection::new(format!("{} matched yara rule {}", file.path, m.rule));
                detection.details = Some(json!({
                    "sha256": file.sha256.to_hex(),
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "rule_uuid": uuid,
                }));
                detection.queue = m
                    .meta
                    .get("queue")
                    .map(|q| q.python_str().trim().to_owned())
                    .filter(|q| !q.is_empty());
                detection.signature_uuid =
                    Some(uuid.clone().unwrap_or_else(|| YARA_RULE_MATCH.to_owned()));
                // ace3's signature version is the commit of the rule's repository
                detection.signature_version = Some(
                    commit
                        .clone()
                        .unwrap_or_else(|| SIGNATURE_VERSION_UNKNOWN.to_owned()),
                );
                detection.signature_family = uuid.as_ref().map(|_| "yara".to_owned());
                result.analyzed.detections.push(detection);
            }

            if m.rule.starts_with("SIP_") {
                for pattern in &m.patterns {
                    if let Some(caps) = SIP_STRING.captures(&pattern.identifier) {
                        push_observable(
                            &mut result.observables,
                            ObservableKind::Indicator,
                            &format!("sip:{}", &caps[1]),
                        );
                    }
                }
            }

            let mut strings = Vec::new();
            let mut context = Vec::new();
            let mut match_context = Vec::new();
            for pattern in &m.patterns {
                let end = (pattern.offset + pattern.length).min(data.len());
                let value = Bytes::from(&data[pattern.offset.min(end)..end]);
                // ace3 reads context, match and context again from the start it found, so a
                // match near the start of the file gets more context after it
                let start = pattern.offset.saturating_sub(context_bytes);
                let stop = (start + context_bytes + pattern.length + context_bytes).min(data.len());
                let around = &data[start..stop];
                strings.push((
                    pattern.offset as u64,
                    pattern.identifier.clone(),
                    value.clone(),
                ));
                context.push((
                    pattern.offset as u64,
                    pattern.identifier.clone(),
                    value,
                    hexdump(around),
                ));
                match_context.push(MatchContext {
                    data: Bytes::from(around),
                    match_offset: (pattern.offset - start) as u64,
                    match_length: pattern.length as u64,
                });
            }
            let meta: Map<String, Value> = m
                .meta
                .iter()
                .map(|(key, value)| {
                    (
                        key.to_owned(),
                        serde_json::to_value(value).unwrap_or(Value::Null),
                    )
                })
                .collect();
            result.details.scan_results.push(ScanResult {
                rule: m.rule.clone(),
                namespace: m.namespace.clone(),
                meta,
                tags: m.tags.clone(),
                commit: commit.clone(),
                ruleset: key.clone(),
                target: file.path.to_string(),
                strings,
                context,
                match_context,
            });

            for tag in &m.tags {
                result.analyzed.add_tag(tag);
                if tag == "whitelisted" {
                    result.analyzed.add_directive("whitelisted");
                }
            }
        }

        let rules: Vec<&str> = matches.iter().map(|m| m.rule.as_str()).collect();
        let mut summary = rules
            .iter()
            .take(20)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        if rules.len() > 20 {
            summary.push_str(&format!(" + {} more", rules.len() - 20));
        }
        result.summary = Some(format!("Yara Scan Results: matched yara rules {summary}"));
        Ok(Outcome::Done(result))
    }
}

fn push_observable(list: &mut Vec<NewObservable>, kind: ObservableKind, value: &str) {
    if !list.iter().any(|o| o.kind == kind && o.value == value) {
        list.push(NewObservable::new(kind, value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hexdump_matches_hexdump_c() {
        assert_eq!(
            hexdump(b"PK\x03\x04hello"),
            "00000000  50 4b 03 04 68 65 6c 6c  6f                       |PK..hello|\n00000009\n"
        );
        assert_eq!(
            hexdump(&[0u8; 48]),
            "00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|\n*\n00000030\n"
        );
        assert_eq!(hexdump(b""), "");
    }
}
