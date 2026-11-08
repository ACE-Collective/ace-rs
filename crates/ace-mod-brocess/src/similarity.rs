//! Look-alike signals between domains, a port of ace3's `saq/domain_similarity.py`, which BEC
//! look-alike telemetry and the thread timeline read.
//!
//! - The registrable domain is tldextract's, from `ace_sdk::domains`' copy of its list.
//! - The punycode form is the `idna` crate's strict UTS 46 where ace3 uses the `idna` package's
//!   IDNA 2008; each falls back to the name as it was when it refuses one.
//! - The confusable skeleton and the mixed-script check read confusable-homoglyphs 3.3.1's data,
//!   which `tools/ace3/dumps/confusables.sh` copies into `data/`: the script of each code point, and
//!   what `is_confusable(.., greedy=True, preferred_aliases=["latin"])` folds each character to.
//! - Damerau-Levenshtein and Jaro-Winkler are jellyfish's, over grapheme clusters as jellyfish
//!   counts them, ported from its Rust core because its crate builds only as a Python extension.

use std::collections::HashMap;
use std::sync::LazyLock;

use unicode_segmentation::UnicodeSegmentation;

/// A Damerau-Levenshtein distance ace3 calls close (inclusive, above 0).
pub const DEFAULT_DL_MAX: usize = 2;
/// A Jaro-Winkler similarity ace3 calls close.
pub const DEFAULT_JW_THRESHOLD: f64 = 0.92;

/// Glyph pairs that read as one letter, folded on both sides of a skeleton.
const MULTIGRAPH_FOLDS: [(&str, &str); 3] = [("rn", "m"), ("vv", "w"), ("cl", "d")];

struct Confusables {
    /// Ranges of code points and their script, in order.
    scripts: Vec<(u32, u32, &'static str)>,
    folds: HashMap<char, String>,
}

fn code_point(hex: &str) -> u32 {
    u32::from_str_radix(hex, 16).unwrap_or_else(|e| panic!("bad code point {hex:?}: {e}"))
}

static CONFUSABLES: LazyLock<Confusables> = LazyLock::new(|| {
    let rows = |text: &'static str| {
        text.lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|line| line.split('\t').collect::<Vec<_>>())
    };
    let scripts = rows(include_str!("data/scripts.tsv"))
        .map(|row| (code_point(row[0]), code_point(row[1]), row[2]))
        .collect();
    let folds = rows(include_str!("data/folds.tsv"))
        .filter_map(|row| {
            let from = char::from_u32(code_point(row[0]))?;
            let to = row[1]
                .split(' ')
                .filter_map(|hex| char::from_u32(code_point(hex)))
                .collect();
            Some((from, to))
        })
        .collect();
    Confusables { scripts, folds }
});

/// confusable-homoglyphs' `alias`: the script of a character, or `Unknown`.
fn alias(c: char) -> &'static str {
    let scripts = &CONFUSABLES.scripts;
    let code = c as u32;
    match scripts.binary_search_by(|(start, end, _)| {
        if code < *start {
            std::cmp::Ordering::Greater
        } else if code > *end {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Equal
        }
    }) {
        Ok(index) => scripts[index].2,
        Err(_) => "Unknown",
    }
}

/// `registrable_domain`: the domain's eTLD+1, lowercased, or the cleaned name when it has none.
pub fn registrable_domain(value: &str) -> String {
    let normalized = ace_sdk::email_threads::py_strip(value).to_lowercase();
    let normalized = normalized.trim_end_matches('.');
    if normalized.is_empty() {
        return String::new();
    }
    ace_sdk::domains::top_domain_under_public_suffix(normalized)
        .unwrap_or_else(|| normalized.to_owned())
}

/// `to_ascii`: the punycode form of a domain, or the cleaned name when it has none.
pub fn to_ascii(domain: &str) -> String {
    let cleaned = ace_sdk::email_threads::py_strip(domain).to_lowercase();
    let cleaned = cleaned.trim_end_matches('.');
    if cleaned.is_empty() {
        return String::new();
    }
    idna::domain_to_ascii_strict(cleaned).unwrap_or_else(|_| cleaned.to_owned())
}

/// `_unicode_fold`: each confusable character as the first of its homoglyphs.
fn unicode_fold(value: &str) -> String {
    value
        .chars()
        .map(|c| match CONFUSABLES.folds.get(&c) {
            Some(fold) => fold.clone(),
            None => c.to_string(),
        })
        .collect()
}

/// `skeleton`: the domain as it reads, with its confusables and multigraphs folded.
pub fn skeleton(domain: &str) -> String {
    let mut folded = unicode_fold(domain).to_lowercase();
    for (multigraph, replacement) in MULTIGRAPH_FOLDS {
        folded = folded.replace(multigraph, replacement);
    }
    folded
}

/// `_is_mixed_script`: characters from more than one script besides COMMON.
pub fn is_mixed_script(value: &str) -> bool {
    let mut scripts: Vec<&str> = value
        .chars()
        .map(alias)
        .filter(|a| *a != "COMMON")
        .collect();
    scripts.sort_unstable();
    scripts.dedup();
    scripts.len() > 1
}

fn non_ascii(value: &str) -> bool {
    value.chars().any(|c| c as u32 > 127)
}

/// `domain_attributes`: what a suspect domain is on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainAttributes {
    pub domain: String,
    pub ascii: String,
    pub punycode: bool,
    pub mixed_script: bool,
    pub non_ascii: bool,
}

pub fn domain_attributes(domain: &str) -> DomainAttributes {
    let registrable = registrable_domain(domain);
    let ascii = to_ascii(&registrable);
    DomainAttributes {
        punycode: ascii.contains("xn--"),
        mixed_script: is_mixed_script(&registrable),
        non_ascii: non_ascii(&registrable),
        domain: registrable,
        ascii,
    }
}

/// `DomainSimilarityResult`: every signal between a suspect domain and a reference.
#[derive(Debug, Clone, PartialEq)]
pub struct DomainSimilarity {
    pub suspect: String,
    pub reference: String,
    pub suspect_ascii: String,
    pub reference_ascii: String,
    pub is_identical: bool,
    pub suspect_punycode: bool,
    pub suspect_mixed_script: bool,
    pub suspect_non_ascii: bool,
    pub skeleton_equal: bool,
    pub damerau_levenshtein: usize,
    pub jaro_winkler: f64,
    pub techniques: Vec<&'static str>,
    pub is_similar: bool,
}

/// `compare_domains` with ace3's default thresholds: both reduced to their registrable domains,
/// every signal computed.
pub fn compare_domains(suspect: &str, reference: &str) -> DomainSimilarity {
    let suspect_reg = registrable_domain(suspect);
    let reference_reg = registrable_domain(reference);
    let is_identical = suspect_reg == reference_reg;
    let skeleton_equal = !is_identical && skeleton(&suspect_reg) == skeleton(&reference_reg);
    let damerau_levenshtein = damerau_levenshtein_distance(&suspect_reg, &reference_reg);
    let jaro_winkler = jaro_winkler_similarity(&suspect_reg, &reference_reg);
    let edit_close = !is_identical
        && ((damerau_levenshtein > 0 && damerau_levenshtein <= DEFAULT_DL_MAX)
            || jaro_winkler >= DEFAULT_JW_THRESHOLD);
    let mut techniques = Vec::new();
    if skeleton_equal {
        techniques.push("confusable_skeleton");
    }
    if edit_close {
        techniques.push("edit_distance");
    }
    let suspect_ascii = to_ascii(&suspect_reg);
    DomainSimilarity {
        suspect_punycode: suspect_ascii.contains("xn--"),
        suspect_mixed_script: is_mixed_script(&suspect_reg),
        suspect_non_ascii: non_ascii(&suspect_reg),
        reference_ascii: to_ascii(&reference_reg),
        suspect_ascii,
        is_similar: !is_identical && !techniques.is_empty(),
        is_identical,
        skeleton_equal,
        damerau_levenshtein,
        jaro_winkler,
        techniques,
        suspect: suspect_reg,
        reference: reference_reg,
    }
}

/// `LocalPartSimilarityResult`: how alike two addresses' local parts are.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalPartSimilarity {
    pub is_exact: bool,
    pub skeleton_equal: bool,
    pub damerau_levenshtein: Option<usize>,
    pub jaro_winkler: f64,
    pub is_similar: bool,
}

/// `local_part`: what comes before the last `@`, lowercased, or nothing without one past the start.
fn local_part(address: &str) -> String {
    let cleaned = ace_sdk::email_threads::py_strip(address).to_lowercase();
    match cleaned.rfind('@') {
        Some(at) if at > 0 => cleaned[..at].to_owned(),
        _ => String::new(),
    }
}

/// `compare_local_parts` with ace3's default thresholds: an identical local part, a confusable
/// one, or one an edit or two away.
pub fn compare_local_parts(suspect: &str, reference: &str) -> LocalPartSimilarity {
    let (suspect, reference) = (local_part(suspect), local_part(reference));
    if suspect.is_empty() || reference.is_empty() {
        return LocalPartSimilarity {
            is_exact: false,
            skeleton_equal: false,
            damerau_levenshtein: None,
            jaro_winkler: 0.0,
            is_similar: false,
        };
    }
    let is_exact = suspect == reference;
    let skeleton_equal = !is_exact && skeleton(&suspect) == skeleton(&reference);
    let damerau_levenshtein = damerau_levenshtein_distance(&suspect, &reference);
    let jaro_winkler = jaro_winkler_similarity(&suspect, &reference);
    let edit_close = !is_exact
        && ((damerau_levenshtein > 0 && damerau_levenshtein <= DEFAULT_DL_MAX)
            || jaro_winkler >= DEFAULT_JW_THRESHOLD);
    LocalPartSimilarity {
        is_exact,
        skeleton_equal,
        damerau_levenshtein: Some(damerau_levenshtein),
        jaro_winkler,
        is_similar: is_exact || skeleton_equal || edit_close,
    }
}

fn graphemes(value: &str) -> Vec<&str> {
    value.graphemes(true).collect()
}

/// jellyfish's `damerau_levenshtein_distance`: the unrestricted distance, over grapheme clusters.
pub fn damerau_levenshtein_distance(s1: &str, s2: &str) -> usize {
    if s1 == s2 {
        return 0;
    }
    let (v1, v2) = (graphemes(s1), graphemes(s2));
    let (len1, len2) = (v1.len(), v2.len());
    let infinite = len1 + len2;
    let mut item_position: HashMap<&str, usize> = HashMap::new();
    let mut score = vec![0usize; (len1 + 2) * (len2 + 2)];
    let idx = |i: usize, j: usize| (len2 + 2) * i + j;
    score[0] = infinite;
    for i in 0..=len1 {
        score[idx(i + 1, 0)] = infinite;
        score[idx(i + 1, 1)] = i;
    }
    for i in 0..=len2 {
        score[idx(0, i + 1)] = infinite;
        score[idx(1, i + 1)] = i;
    }
    for i in 1..=len1 {
        let mut db = 0;
        for j in 1..=len2 {
            let i1 = *item_position.entry(v2[j - 1]).or_insert(0);
            let j1 = db;
            let mut cost = 1;
            if v1[i - 1] == v2[j - 1] {
                cost = 0;
                db = j;
            }
            score[idx(i + 1, j + 1)] = (score[idx(i, j)] + cost)
                .min(score[idx(i + 1, j)] + 1)
                .min(score[idx(i, j + 1)] + 1)
                .min(score[idx(i1, j1)] + (i - i1 - 1) + 1 + (j - j1 - 1));
        }
        item_position.insert(v1[i - 1], i);
    }
    score[idx(len1 + 1, len2 + 1)]
}

/// jellyfish's `jaro_winkler_similarity`, without its long-string tolerance, over grapheme
/// clusters. Either string empty is 0.
pub fn jaro_winkler_similarity(s1: &str, s2: &str) -> f64 {
    let (s1, s2) = (graphemes(s1), graphemes(s2));
    let (s1_len, s2_len) = (s1.len(), s2.len());
    if s1_len == 0 || s2_len == 0 {
        return 0.0;
    }
    let min_len = s1_len.min(s2_len);
    let search_range = (s1_len.max(s2_len) / 2).saturating_sub(1);
    let mut s1_flags = vec![false; s1_len];
    let mut s2_flags = vec![false; s2_len];
    let mut common = 0usize;
    for (i, c) in s1.iter().enumerate() {
        let low = i.saturating_sub(search_range);
        let high = (i + search_range).min(s2_len - 1);
        for j in low..=high {
            if !s2_flags[j] && s2[j] == *c {
                s1_flags[i] = true;
                s2_flags[j] = true;
                common += 1;
                break;
            }
        }
    }
    if common == 0 {
        return 0.0;
    }
    let mut k = 0;
    let mut transpositions = 0usize;
    for (i, flagged) in s1_flags.iter().enumerate() {
        if *flagged {
            let mut j = k;
            while j < s2_len {
                if s2_flags[j] {
                    k = j + 1;
                    break;
                }
                j += 1;
            }
            if j < s2_len && s1[i] != s2[j] {
                transpositions += 1;
            }
        }
    }
    let transpositions = (transpositions / 2) as f64;
    let commonf = common as f64;
    let mut weight =
        (commonf / s1_len as f64 + commonf / s2_len as f64 + (commonf - transpositions) / commonf)
            / 3.0;
    if weight > 0.7 {
        let mut i = 0;
        while i < min_len.min(4) && s1[i] == s2[i] {
            i += 1;
        }
        if i > 0 {
            weight += i as f64 * 0.1 * (1.0 - weight);
        }
    }
    weight
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_reduce_and_fold_as_ace3s() {
        assert_eq!(registrable_domain(" Mail.Example.CO.UK. "), "example.co.uk");
        assert_eq!(registrable_domain(""), "");
        assert_eq!(registrable_domain("intranet"), "intranet");
        // cyrillic а in place of a
        assert_eq!(skeleton("ex\u{430}mple.com"), "example.com");
        assert_eq!(skeleton("rnicrosoft.com"), "microsoft.com");
        assert!(is_mixed_script("ex\u{430}mple.com"));
        assert!(!is_mixed_script("example.com"));
        assert!(!is_mixed_script("пример.рф"));
        assert_eq!(to_ascii("пример.рф"), "xn--e1afmkfd.xn--p1ai");
        assert_eq!(to_ascii("Example.com."), "example.com");
    }

    #[test]
    fn distances_are_jellyfishs() {
        // the values jellyfish 1.3.0 gives in ace3's image
        assert_eq!(
            damerau_levenshtein_distance("example.com", "exmaple.com"),
            1
        );
        assert_eq!(damerau_levenshtein_distance("ca", "abc"), 2);
        assert_eq!(damerau_levenshtein_distance("", "abc"), 3);
        assert_eq!(
            jaro_winkler_similarity("example.com", "examp1e.com"),
            0.9636363636363636
        );
        assert_eq!(
            jaro_winkler_similarity("martha", "marhta"),
            0.9611111111111111
        );
        assert_eq!(jaro_winkler_similarity("", "a"), 0.0);
        assert_eq!(jaro_winkler_similarity("abc", "xyz"), 0.0);
        // a letter and its combining accent are one grapheme
        assert_eq!(damerau_levenshtein_distance("cafe\u{301}", "cafe"), 1);
    }

    #[test]
    fn a_look_alike_is_similar_and_the_same_domain_isnt() {
        let compared = compare_domains("mail.examp1e.com", "example.com");
        assert_eq!(compared.suspect, "examp1e.com");
        assert!(!compared.is_identical);
        // the digit 1 reads as an l
        assert_eq!(
            compared.techniques,
            ["confusable_skeleton", "edit_distance"]
        );
        assert!(compared.is_similar);
        let same = compare_domains("example.com", "www.example.com");
        assert!(same.is_identical);
        assert!(!same.is_similar);
        let homoglyph = compare_domains("ex\u{430}mple.com", "example.com");
        assert_eq!(
            homoglyph.techniques,
            ["confusable_skeleton", "edit_distance"]
        );
        assert!(homoglyph.suspect_punycode && homoglyph.suspect_mixed_script);
        assert_eq!(homoglyph.suspect_ascii, "xn--exmple-4nf.com");
        assert_eq!(homoglyph.jaro_winkler, 0.9515151515151515);
    }
}
