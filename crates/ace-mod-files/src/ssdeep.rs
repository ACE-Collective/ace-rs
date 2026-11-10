//! ace3's `SsdeepAnalyzer` (`saq/modules/file_analysis/ssdeep.py`, PLAN.md 7.5 batch 10): a file of
//! 1 KB to `maximum_size` is matched by its fuzzy hash against a list of known hashes, and one that
//! scores `ssdeep_match_threshold` or more against any is tagged `ssdeep` and sandboxed.
//!
//! ace3 runs `ssdeep -m <list> <file>` (ssdeep 2.14.1) and reads its matches. Here the hash is the
//! `fuzzyhash` crate's, which gives ssdeep's hashes on every file batch 2 measured, and the score is
//! `compare`, which follows ssdeep 2.14.1's `fuzzy_compare`. fuzzyhash's own comparison drops
//! characters that aren't in a run when it shortens runs, and scores some files 100 that ssdeep
//! scores 0 (`docs/measurements/ssdeep.md`), so it isn't used.
//!
//! The list is read when the module is built, before the task process contains itself: ace3's
//! `ssdeep_hashes` file, in ssdeep's own format, as `ssdeep -s` writes it. The module is off unless a
//! site turns it on, as ace3's is, and then it needs the list.

use std::fs;
use std::path::PathBuf;

use ace_results::types::ssdeep::{SsdeepAnalysis, SsdeepMatch};
use ace_results::{ObservableKind, ResultEnvelope};
use ace_sdk::{Module, ModuleError, Outcome, Parser, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

/// ace3's `DIRECTIVE_SANDBOX`.
const SANDBOX: &str = "sandbox";
/// The smallest file ace3 hashes.
const MIN_SIZE: u64 = 1024;
/// ssdeep's header line.
const HEADER: &str = "ssdeep,1.1--blocksize:hash:hash,filename";

/// ace3's section of the module.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct SsdeepSettings {
    /// The list of known hashes, as `ssdeep -s` writes it. ace3's default is `etc/ssdeep_hashes`
    /// under its home, which ace4 has no counterpart of, so a site names it.
    pub ssdeep_hashes: Option<PathBuf>,
    /// The largest file hashed, in bytes.
    pub maximum_size: u64,
    /// The score, out of 100, at which a match tags the file.
    pub ssdeep_match_threshold: u32,
}

impl Default for SsdeepSettings {
    /// ace3's `saq.default.yaml`.
    fn default() -> Self {
        SsdeepSettings {
            ssdeep_hashes: None,
            maximum_size: 2_048_000,
            ssdeep_match_threshold: 90,
        }
    }
}

/// A hash in the list, and the name ssdeep prints for its file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Known {
    pub hash: String,
    pub file: String,
}

/// The ssdeep module.
pub struct SsdeepAnalyzer {
    known: Vec<Known>,
    settings: SsdeepSettings,
}

impl Module for SsdeepAnalyzer {
    const NAME: &'static str = "ssdeep";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const ENABLED_BY_DEFAULT: bool = false;
    type Output = SsdeepAnalysis;
    type Settings = SsdeepSettings;

    /// Reads the list, as ace3's `verify_environment` checks it exists.
    fn init(settings: &SsdeepSettings) -> Result<Self, ModuleError> {
        let path = settings.ssdeep_hashes.as_ref().ok_or_else(|| {
            ModuleError::other("ssdeep needs ssdeep_hashes, the list of known hashes")
        })?;
        let text =
            fs::read(path).map_err(|e| ModuleError::other(format!("{}: {e}", path.display())))?;
        let known = parse_known(&String::from_utf8_lossy(&text))
            .map_err(|e| ModuleError::other(format!("{}: {e}", path.display())))?;
        Ok(SsdeepAnalyzer {
            known,
            settings: settings.clone(),
        })
    }
}

/// The hashes of a list in ssdeep's format. ssdeep refuses a file without its header; a line that
/// isn't a hash and a quoted name it skips.
pub fn parse_known(text: &str) -> Result<Vec<Known>, String> {
    let mut lines = text.lines();
    if lines.next().map(str::trim_end) != Some(HEADER) {
        return Err("not a list of ssdeep hashes".to_owned());
    }
    let mut known = Vec::new();
    for line in lines {
        let line = line.trim_end_matches('\r');
        let Some((hash, name)) = line.split_once(",\"") else {
            continue;
        };
        let Some(name) = name.strip_suffix('"') else {
            continue;
        };
        if parse_hash(hash).is_none() {
            continue;
        }
        known.push(Known {
            hash: hash.to_owned(),
            file: name.replace("\\\"", "\""),
        });
    }
    Ok(known)
}

/// A hash's block size and its two strings.
fn parse_hash(hash: &str) -> Option<(u64, &[u8], &[u8])> {
    let (size, rest) = hash.split_once(':')?;
    let (first, second) = rest.split_once(':')?;
    let size: u64 = size.parse().ok()?;
    let second = second.split(',').next()?;
    Some((size, first.as_bytes(), second.as_bytes()))
}

/// A string with every run of more than three of one character cut to three, as ssdeep's
/// `copy_eliminate_sequences`.
fn eliminate_sequences(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    for (i, &c) in text.iter().enumerate() {
        if i >= 3 && c == text[i - 1] && c == text[i - 2] && c == text[i - 3] {
            continue;
        }
        out.push(c);
    }
    out
}

const ROLLING_WINDOW: usize = 7;
const SPAMSUM_LENGTH: u32 = 64;
const MIN_BLOCKSIZE: u64 = 3;

/// ssdeep's rolling hash.
#[derive(Default)]
struct Roll {
    window: [u8; ROLLING_WINDOW],
    h1: u32,
    h2: u32,
    h3: u32,
    n: usize,
}

impl Roll {
    fn hash(&mut self, c: u8) {
        let c = u32::from(c);
        self.h2 = self.h2.wrapping_sub(self.h1);
        self.h2 = self.h2.wrapping_add(ROLLING_WINDOW as u32 * c);
        self.h1 = self.h1.wrapping_add(c);
        self.h1 = self
            .h1
            .wrapping_sub(u32::from(self.window[self.n % ROLLING_WINDOW]));
        self.window[self.n % ROLLING_WINDOW] = c as u8;
        self.n += 1;
        self.h3 <<= 5;
        self.h3 ^= c;
    }

    fn sum(&self) -> u32 {
        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

/// Whether the strings share a run of `ROLLING_WINDOW` characters whose rolling hash isn't 0, as
/// ssdeep's `has_common_substring` finds one.
fn has_common_substring(s1: &[u8], s2: &[u8]) -> bool {
    if s1.len() < ROLLING_WINDOW || s2.len() < ROLLING_WINDOW {
        return false;
    }
    let mut hashes = vec![0u32; s1.len()];
    let mut roll = Roll::default();
    for (i, &c) in s1.iter().enumerate() {
        roll.hash(c);
        hashes[i] = roll.sum();
    }
    let mut roll = Roll::default();
    for (i, &c) in s2.iter().enumerate() {
        roll.hash(c);
        if i < ROLLING_WINDOW - 1 {
            continue;
        }
        let sum = roll.sum();
        for j in ROLLING_WINDOW - 1..s1.len() {
            if hashes[j] != 0
                && hashes[j] == sum
                && s2[i + 1 - ROLLING_WINDOW..=i] == s1[j + 1 - ROLLING_WINDOW..=j]
            {
                return true;
            }
        }
    }
    false
}

/// The weighted edit distance ssdeep uses: inserting or removing a character costs 1, changing one 2.
fn edit_distance(s1: &[u8], s2: &[u8]) -> u32 {
    let mut previous: Vec<u32> = (0..=s2.len() as u32).collect();
    let mut current = vec![0u32; s2.len() + 1];
    for (i, &a) in s1.iter().enumerate() {
        current[0] = i as u32 + 1;
        for (j, &b) in s2.iter().enumerate() {
            let insert = previous[j + 1] + 1;
            let remove = current[j] + 1;
            let change = previous[j] + if a == b { 0 } else { 2 };
            current[j + 1] = insert.min(remove).min(change);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[s2.len()]
}

/// ssdeep's `score_strings`.
fn score_strings(s1: &[u8], s2: &[u8], block_size: u64) -> u32 {
    if !has_common_substring(s1, s2) {
        return 0;
    }
    let mut score = edit_distance(s1, s2);
    score = score * SPAMSUM_LENGTH / (s1.len() + s2.len()) as u32;
    score = 100 * score / SPAMSUM_LENGTH;
    let score = 100u32.saturating_sub(score);
    // a small block size doesn't get a big score for a short match
    let uncapped = (99 + ROLLING_WINDOW as u64) / ROLLING_WINDOW as u64 * MIN_BLOCKSIZE;
    if block_size >= uncapped {
        return score;
    }
    let cap = block_size / MIN_BLOCKSIZE * s1.len().min(s2.len()) as u64;
    score.min(u32::try_from(cap).unwrap_or(u32::MAX))
}

/// ssdeep 2.14.1's `fuzzy_compare` of two hashes: 0 to 100, 0 for hashes that can't be compared.
pub fn compare(a: &str, b: &str) -> u32 {
    let (Some((size1, a1, a2)), Some((size2, b1, b2))) = (parse_hash(a), parse_hash(b)) else {
        return 0;
    };
    if size1 != size2 && size1.checked_mul(2) != Some(size2) && size2.checked_mul(2) != Some(size1)
    {
        return 0;
    }
    let (a1, a2, b1, b2) = (
        eliminate_sequences(a1),
        eliminate_sequences(a2),
        eliminate_sequences(b1),
        eliminate_sequences(b2),
    );
    if size1 == size2 && a1 == b1 && a2 == b2 {
        return 100;
    }
    if size1 == size2 {
        score_strings(&a1, &b1, size1).max(score_strings(&a2, &b2, size1 * 2))
    } else if size1 * 2 == size2 {
        score_strings(&a2, &b1, size2)
    } else {
        score_strings(&a1, &b2, size1)
    }
}

/// The file's ssdeep hash.
pub fn hash(data: &[u8]) -> String {
    let mut hash = fuzzyhash::FuzzyHash::new(data);
    hash.finalize();
    hash.to_string()
}

fn summary(matches: &[SsdeepMatch]) -> Option<String> {
    let best = matches.iter().map(|m| m.score).max()?;
    Some(format!(
        "Ssdeep Analysis ({} matches {best}% highest match)",
        matches.len()
    ))
}

impl Parser for SsdeepAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<SsdeepSettings>,
    ) -> Result<Outcome<SsdeepAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        if file.size < MIN_SIZE {
            return Ok(Outcome::Skipped("too small for ssdeep".to_owned()));
        }
        if file.size > self.settings.maximum_size {
            return Ok(Outcome::Skipped("too large for ssdeep".to_owned()));
        }
        let hash = hash(&fs::read(&file.local_path)?);
        let mut matches = Vec::new();
        for known in &self.known {
            // ssdeep prints a match that scores more than 0, and ace3 keeps those past its threshold
            let score = compare(&hash, &known.hash);
            if score > 0 && score >= self.settings.ssdeep_match_threshold {
                matches.push(SsdeepMatch {
                    file: known.file.clone(),
                    score,
                });
            }
        }
        if matches.is_empty() {
            return Ok(Outcome::Skipped("no match".to_owned()));
        }
        let mut result = ResultEnvelope::new(SsdeepAnalysis::default());
        result.summary = summary(&matches);
        result.details.matches = matches;
        result.analyzed.tags.push("ssdeep".to_owned());
        result.analyzed.directives.push(SANDBOX.to_owned());
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_are_cut_to_three() {
        assert_eq!(eliminate_sequences(b"8EEEEEE4"), b"8EEE4");
        assert_eq!(eliminate_sequences(b"aaabaaaa"), b"aaabaaa");
        assert_eq!(eliminate_sequences(b"ab"), b"ab");
    }

    /// The case fuzzyhash scores 100: two hashes of one repeated character, which differ in their
    /// last, share no seven characters once their runs are cut.
    #[test]
    fn hashes_of_a_repeated_run_share_nothing() {
        let a = format!("12:X{}D:l", "g".repeat(62));
        let b = format!("12:X{}5:LJwCRZGNE", "g".repeat(62));
        assert_eq!(compare(&a, &b), 0);
        assert_eq!(compare(&a, &a), 100);
    }

    #[test]
    fn the_known_hashes_read_as_ssdeep_writes_them() {
        let known = parse_known(
            "ssdeep,1.1--blocksize:hash:hash,filename\n96:Ak:uF,\"base_text\"\nnot a hash\n\
             3:H:H,\"say \\\"hi\\\"\"\n",
        )
        .unwrap();
        assert_eq!(
            known,
            [
                Known {
                    hash: "96:Ak:uF".into(),
                    file: "base_text".into()
                },
                Known {
                    hash: "3:H:H".into(),
                    file: "say \"hi\"".into()
                },
            ]
        );
        assert!(parse_known("96:Ak:uF,\"x\"\n").is_err());
    }

    #[test]
    fn block_sizes_must_be_equal_or_twice_and_a_small_one_caps_the_score() {
        assert_eq!(compare("3:abcdefgh:abcd", "12:abcdefgh:abcd"), 0);
        // the second string of size 3 against the first of size 6: the same, but capped at
        // 6 / 3 * 8
        assert_eq!(compare("3:qqqqqqqq:abcdefgh", "6:abcdefgh:xyz"), 16);
    }

    /// docs/measurements/ssdeep.md: every file `tools/ace3/ssdeep/gen.py` writes, hashed and
    /// matched against the base files' hashes, as ssdeep 2.14.1 answered in ace3's container. Run with
    /// `ACE4_SSDEEP_DIR` naming a directory of `files/`, `all_hashes` (`ssdeep -s -b *`), `hashes_base`
    /// and `matches` (`ssdeep -s -m hashes_base` of each file), as that page says.
    #[test]
    #[ignore = "needs ssdeep's answers, made in ace3's container"]
    fn hashes_and_scores_are_ssdeeps() {
        let dir = PathBuf::from(std::env::var("ACE4_SSDEEP_DIR").expect("ACE4_SSDEEP_DIR"));
        let all = fs::read_to_string(dir.join("all_hashes")).unwrap();
        let known = parse_known(&fs::read_to_string(dir.join("hashes_base")).unwrap()).unwrap();
        let mut hashes = 0;
        for entry in parse_known(&all).unwrap() {
            let data = fs::read(dir.join("files").join(&entry.file)).unwrap();
            assert_eq!(hash(&data), entry.hash, "{}", entry.file);
            hashes += 1;
        }
        let mut ours = Vec::new();
        let mut names: Vec<String> = fs::read_dir(dir.join("files"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        for name in &names {
            let path = dir.join("files").join(name);
            let file_hash = hash(&fs::read(&path).unwrap());
            for k in &known {
                let score = compare(&file_hash, &k.hash);
                if score > 0 {
                    ours.push(format!(
                        "{name} {} ({score})",
                        k.file.rsplit('/').next().unwrap()
                    ));
                }
            }
        }
        let mut theirs: Vec<String> = fs::read_to_string(dir.join("matches"))
            .unwrap()
            .lines()
            .map(|line| {
                let (file, rest) = line.split_once(" matches ").unwrap();
                let (_, matched) = rest.split_once(':').unwrap();
                format!(
                    "{} {}",
                    file.rsplit('/').next().unwrap(),
                    matched.rsplit('/').next().unwrap()
                )
            })
            .collect();
        ours.sort();
        theirs.sort();
        println!(
            "{hashes} hashes the same; {} matches here, {} from ssdeep",
            ours.len(),
            theirs.len()
        );
        assert_eq!(ours, theirs);
    }
}
